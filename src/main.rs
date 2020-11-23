extern crate indicatif;
extern crate clap;
extern crate crossbeam;
extern crate ring;
extern crate num_cpus;

use std::fmt;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Result, Read, Write, BufWriter};
use std::ffi::OsString;

use std::fs::{self};
use std::path::{PathBuf};
use std::sync::{Mutex, Arc};

use crossbeam::channel::Sender;
use crossbeam::channel::unbounded;
use crossbeam::thread;

use clap::{Arg, App};

use ring::digest::{Context, Digest, SHA256};

use data_encoding::HEXUPPER;

use indicatif::{ProgressBar, ProgressStyle};

use rand::seq::SliceRandom;

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
    let mut buffer = [0; 8*1024];

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
    path: PathBuf,
}

fn visit_dirs(path_sender: Sender<Option<HashTask>>, side: DirSide, dir: PathBuf) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path_loc = entry.path();
            if path_loc.is_dir() {
                visit_dirs(path_sender.clone(), side, path_loc)?;
            } else {
                path_sender.send(Some(HashTask { side, path: entry.path() })).unwrap();
            }
        }
    }
    Ok(())
}

fn send_cancellation_tokens(path_sender: Sender<Option<HashTask>>, thread_count: i32) {
    for _ in 0..thread_count {
        path_sender.send(None).unwrap();
    }
}

fn write_missing(matching: &HashMap<OsString, HashResult>, side: DirSide) -> std::io::Result<()> {
    let missing_left = File::create(format!("missing-{}.txt", side))?;
    let mut buf_writer_missing = BufWriter::new(missing_left);
    matching.iter()
        .filter(|&(_k, v)| v.side != side)
        .for_each(|(_k, v)| { writeln!(&mut buf_writer_missing, "missing {}: {}", side, v.path.display()).unwrap() });
    buf_writer_missing.flush()?;

    Ok(())
}

fn write_results(matching: &HashMap<OsString, HashResult>, missmatches: Vec<(HashResult, HashResult)>) -> std::io::Result<()> {
    let mismatched_file = File::create("mismatched.txt")?;
    let mut buf_writer_mismatch_file = BufWriter::new(mismatched_file);

    for (first, second) in missmatches {
        let first_path_os = first.path.into_os_string().into_string().unwrap_or("error".to_string());
        let second_path_os = second.path.into_os_string().into_string().unwrap_or("error".to_string());
        if first.side == DirSide::Left {
            writeln!(&mut buf_writer_mismatch_file, "mismatch: {} - {} left: {} - right: {}", first_path_os, second_path_os, first.hash, second.hash)?;
        } else {
            writeln!(&mut buf_writer_mismatch_file, "mismatch: {} - {} left: {} - right: {}", second_path_os, first_path_os, second.hash, first.hash)?;
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
    hash: String,
}

struct Config {
    left: PathBuf,
    right: PathBuf,
    total_threads: i32,
}

fn start_comparing(cfg: Config) {
    let thread_count = cfg.total_threads;
    let source_paths = vec![(DirSide::Left, cfg.left.clone()), (DirSide::Right, cfg.right.clone())];

    thread::scope(|s| {
        let walking_finished = Arc::new(Mutex::new(0));
        let (tx_walked_paths, rx_walked_paths) = unbounded();

        for (side, base_dir) in source_paths {
            let tx_first = tx_walked_paths.clone();
            let tx_second = tx_walked_paths.clone();
            let walking_finished_cnt = walking_finished.clone();

            s.spawn(move |_| {
                visit_dirs(tx_first, side, base_dir).unwrap();
                println!("Finished walking {}", side);
                let mut num = walking_finished_cnt.lock().unwrap();
                *num += 1;
                if *num > 1 {
                    send_cancellation_tokens(tx_second, thread_count);
                }
            });
        }

        let (tx_max_count, rx_max_count) = unbounded();
        let (tx_paths_to_check, receiver_paths_to_check) = unbounded();
        s.spawn(move |_| {
            let mut all_hashtasks:Vec<HashTask> = vec![];

            //Receive all until cancellation
            while let Ok(Some(ht)) = rx_walked_paths.recv() {
                all_hashtasks.push(ht);
            }

            //shuffle
            let mut rng = rand::thread_rng();
            all_hashtasks.shuffle(&mut rng);

            println!("Start comparing files:");
            tx_max_count.send(all_hashtasks.len() as u64).unwrap();

            //Send
            while let Some(ht) = all_hashtasks.pop() {
                tx_paths_to_check.send(Some(ht)).unwrap();
            }

            //Send CancellationToken
            tx_paths_to_check.send(None).unwrap();
        });

        let (tx_hashresults, rx_resultmerger) = unbounded();
        for _ in 0..thread_count {
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
            let mut matching: HashMap<OsString, HashResult> = HashMap::new();
            let mut notmatched: Vec<(HashResult, HashResult)> = Vec::new();

            let pb = ProgressBar::new(rx_max_count.recv().unwrap());
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:70.cyan/blue}] {pos:>9}/{len:9} ({eta})")
                .progress_chars("#>-"));


            while let Ok(o_hr) = rx_resultmerger.recv() {
                match o_hr {
                    Some(hr) => {
                        let rel_path = match hr.side {
                            DirSide::Left => hr.path.strip_prefix(cfg.left.to_str().unwrap()),
                            DirSide::Right => hr.path.strip_prefix(cfg.right.to_str().unwrap()),
                        };

                        if let Ok(path) = rel_path {
                            let path_os = path.as_os_str().to_os_string();
                            match matching.get(&path_os) {
                                Some(_hr_other) => { //It's already one time here
                                    let hr_other_side = matching.remove(&path_os).unwrap();
                                    if hr_other_side.hash != hr.hash {
                                        notmatched.push((hr, hr_other_side));
                                    }
                                }
                                None => {
                                    matching.insert(path_os, hr);
                                }
                            }
                        }
                        pb.inc(1);
                    }
                    None => {
                        cnt_cancellation_tokens_received += 1;
                        if cnt_cancellation_tokens_received > cfg.total_threads {
                            pb.finish_with_message("writing results...");
                            if matching.len() == 0 && notmatched.len() == 0 {
                                println!("Directories exactly the same!");
                            } else {
                                match write_results(&matching, notmatched) {
                                    Err(e) => println!("Failed writing results! {}", e),
                                    Ok(_) => println!("Results written!")
                                }
                                println!("finished processing");
                            }
                            break;
                        }
                    }
                }
            }
        });
    }).unwrap()
}

fn main() {
    let matches = App::new("Parallel directory compare")
        .version("0.0.1")
        .author("Christoph Doblander")
        .about("Compares the content of two directories")
        .arg(Arg::with_name("LEFT_DIRECTORY")
            .short("l")
            .long("left")
            .help("Sets the left directory")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("RIGHT_DIRECTORY")
            .short("r")
            .long("right")
            .help("Sets the right directory")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("THREAD_COUNT")
            .short("t")
            .long("threads")
            .help("Sets how many threads should be used for hashing")
            .takes_value(true))
        .get_matches();

    let dir_left: String = String::from(matches.value_of("LEFT_DIRECTORY").unwrap());
    let left = PathBuf::from(dir_left.as_str());
    if !left.exists() {
        eprintln!("Left directory does not exist");
        return;
    }

    let dir_right: String = String::from(matches.value_of("RIGHT_DIRECTORY").unwrap());
    let right = PathBuf::from(dir_right.as_str());
    if !right.exists() {
        eprintln!("Right directory does not exist");
        return;
    }

    let mut total_threads: i32 = num_cpus::get() as i32;
    if let Some(thread_count_str) = matches.value_of("THREAD_COUNT") {
	    if let Ok(thread_count_int) = thread_count_str.parse::<i32>() {
	        total_threads = thread_count_int;
	    } else {
            eprintln!("Could not parse thread count");
            return;
        }
    }

    let cfg = Config{left, right, total_threads };
    start_comparing(cfg)
}
