extern crate argparse;
extern crate crossbeam;
extern crate ring;

use std::fs::{self};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Arc};

use crossbeam::channel::{Sender};
use crossbeam::channel::{unbounded};
use crossbeam::thread;
use argparse::{ArgumentParser, StoreTrue, Store};

use ring::digest::{Context, Digest, SHA256};

use data_encoding::HEXUPPER;

use std::fmt;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Result, Read, Write, BufWriter};
use std::ffi::{OsString};

#[derive(Copy, Clone, PartialEq)]
enum DirSide {
    Left,
    Right,
}

impl fmt::Display for DirSide {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DirSide::Left => write!(f, "left"),
            DirSide::Right => write!(f, "right"),
        }
    }
}

fn sha256_digest(path: PathBuf) -> Result<Digest> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}

struct HashTask {
    side: DirSide,
    path: PathBuf
}

fn visit_dirs(path_sender: Sender<Option<HashTask>>, side: DirSide, dir: &Path) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path_loc = entry.path();
            if path_loc.is_dir() {
                visit_dirs(path_sender.clone(), side, path_loc.as_path())?;
            } else {
                path_sender.send(Some(HashTask {side: side, path: entry.path()})).unwrap();
            }
        }
    }
    Ok(())
}

fn send_cancellation_tokens(path_sender: Sender<Option<HashTask>>, thread_count: usize) {
    for _ in 0..thread_count {
        path_sender.send(None).unwrap();
    }
}

fn write_missing(matching: &HashMap<OsString, HashResult>, side: DirSide) -> std::io::Result<()> {
    let missing_left = File::create(format!("missing-{}.txt", side))?;
    let mut buf_writer_missing = BufWriter::new(missing_left);
    matching.iter()
        .filter(|&(_k, v)| v.side != side)
        .for_each(|(_k, v)| { writeln!(&mut buf_writer_missing, "missing {}: {}", side, v.path.display()).unwrap()}); //TODO! write errors are not handled
    buf_writer_missing.flush()?;

    Ok(())
}

fn write_results(matching: &HashMap<OsString, HashResult>, missmatches: Vec<(HashResult, HashResult)>) -> std::io::Result<()> {

    let mismatched_file = File::create("mismatched.txt")?;
    let mut buf_writer_mismatch_file = BufWriter::new(mismatched_file);

    for (first, second) in missmatches {
        let first_path_os = first.path.into_os_string();
        let second_path_os = second.path.into_os_string();
        if first.side == DirSide::Left {
            writeln!(&mut buf_writer_mismatch_file, "mismatch: {} - {} left: {} - right: {}", first_path_os.to_string_lossy(), second_path_os.to_string_lossy(), first.hash, second.hash)?;
        } else {
            writeln!(&mut buf_writer_mismatch_file, "mismatch: {} - {} left: {} - right: {}", second_path_os.to_string_lossy(), first_path_os.to_string_lossy(), second.hash, first.hash)?;
        }
    }
    buf_writer_mismatch_file.flush()?;


    write_missing(matching, DirSide::Left)?;
    write_missing(matching, DirSide::Right)?;


    Ok(())
}

struct HashResult {
    side: DirSide,
    path: PathBuf,
    hash: String
}

fn main() {
    let mut verbose = false;

    let mut dir_left:String = String::from("None");
    let mut dir_right:String = String::from("None");
    let mut total_threads:usize = 2;

    {  // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        {
            ap.set_description("Compares the content of two directories");
            ap.refer(&mut verbose)
                .add_option(&["-v", "--verbose"], StoreTrue,
                            "Be verbose");
            ap.refer(&mut dir_left)
                .add_option(&["-l", "--left"], Store,
                            "Left Directory")
                .required();
            ap.refer(&mut dir_right)
                .add_option(&["-r", "--right"], Store,
                            "Right Directory")
                .required();

            ap.refer(&mut total_threads)
                .add_option(&["-c", "--cores"], Store,
                            "Total amount of threads to be used for checking the content of the file, > 0");

            ap.parse_args_or_exit();
        }

        //if total_threads < 1 {
        //    todo!("to less threads, validation");
        //}

    }


    let str_dir_left = dir_left.as_str();
    let str_dir_right = dir_right.as_str();

    let source_paths = vec![(DirSide::Left, Path::new(str_dir_left)), (DirSide::Right, Path::new(str_dir_right))];

    thread::scope(|s| {
        let walking_finished = Arc::new(Mutex::new(0));
        let (tx_paths_to_check, receiver_paths_to_check) = unbounded();

        for (side, base_dir) in source_paths {
            let tx_first = tx_paths_to_check.clone();
            let tx_second = tx_paths_to_check.clone();
            let walking_finished_cnt = walking_finished.clone();
            s.spawn(move |_| {
                visit_dirs(tx_first, side, base_dir).unwrap();
                let mut num = walking_finished_cnt.lock().unwrap();
                *num += 1;
                if *num > 1 {
                    send_cancellation_tokens(tx_second, total_threads);
                }
            });
        }

        let (tx_hashresults, rx_resultmerger) = unbounded();
        for _ in 0..total_threads {
            let rx_first = receiver_paths_to_check.clone();
            let tx_first = tx_hashresults.clone();
            s.spawn(move |_| {
                while let Ok(Some(ht)) = rx_first.recv() {
                    let digest = sha256_digest(ht.path.clone()).unwrap();
                    let hash = HEXUPPER.encode(digest.as_ref());

                    let hr = HashResult { side: ht.side, path: ht.path, hash };
                    tx_first.send(Some(hr)).unwrap();
                }
                tx_first.send(None).unwrap();
            });
        }

        s.spawn(move |_| {
            let mut cnt_cancellation_tokens_received = 1;
            let mut matching:HashMap<OsString, HashResult> = HashMap::new();
            let mut notmatched:Vec<(HashResult, HashResult)> = Vec::new();

            while let Ok(o_hr) = rx_resultmerger.recv() {
                match o_hr {
                    Some(hr) => {
                        let rel_path = match hr.side {
                            DirSide::Left => hr.path.strip_prefix(str_dir_left),
                            DirSide::Right => hr.path.strip_prefix(str_dir_right),
                        };

                        match rel_path {
                            Ok(path) => {
                                let path_os = path.as_os_str().to_os_string();
                                match matching.get(&path_os) {
                                    Some(_hr_other) => { //It's already one time here
                                        let hr_other_side = matching.remove(&path_os).unwrap();
                                        if hr_other_side.hash != hr.hash {
                                            if hr.side == DirSide::Left {
                                                println!("mismatch: {} left: {} - right: {}", path_os.to_string_lossy(), hr.hash, hr_other_side.hash);
                                            } else {
                                                println!("mismatch: {} left: {} - right: {}", path_os.to_string_lossy(), hr_other_side.hash, hr.hash);
                                            }
                                            notmatched.push((hr, hr_other_side));
                                        }
                                    }
                                    None => {
                                        matching.insert(path_os, hr);
                                    }
                                }
                            }
                            Err(_) => {
                                todo!();
                            }
                        }
                    }
                    None => {
                        cnt_cancellation_tokens_received +=1;
                        if cnt_cancellation_tokens_received > total_threads {
                            if matching.len() == 0 && notmatched.len() == 0 {
                                println!("Directories exactly the same!");
                            } else {

                                match write_results(&matching, notmatched) {
                                    Err(e) => println!("Failed writing results! {}", e),
                                    Ok(_) => println!("Results written!")
                                }

                                //then print&store missing left
                                matching.iter()
                                    .filter(|&(_k, v)| v.side == DirSide::Right)
                                    .for_each(|(_k, v)| { println!("missing left: {}", v.path.display()) });

                                //then print&store missing right
                                matching.iter()
                                    .filter(|&(_k, v)| v.side == DirSide::Left)
                                    .for_each(|(_k, v)| { println!("missing right: {}", v.path.display()) });


                                println!("finished processing");
                            }
                            break;
                        }
                    }
                }
            }
        });
    }).unwrap();
}
