use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::net::{TcpStream, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
// use std::thread;

use chrono::{DateTime, TimeZone, Utc, TimeDelta};
use native_tls::{Certificate, TlsConnector};
use x509_parser::prelude::*;
use sha2::{self, Digest};
use hex;

use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

use indicatif::{ProgressBar, ProgressStyle};



const SOCKET_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const DAYS_THRESHOLD: i64 = 30;
const THREAD_COUNT: usize = 40;

fn pluralize(word: &str, count: i64) -> String {
    format!("{} {}{}", count, word, if count == 1 {""} else {"s"})
}

fn format_time_remaining(duration: chrono::Duration) -> String {
    let days: i64 = duration.num_days();
    let hours: i64 = (duration.num_hours() % 24) as i64;
    let minutes: i64 = (duration.num_minutes() % 60) as i64;
    format!(
        "{} {} {}",
        pluralize("day", days),
        pluralize("hour", hours),
        pluralize("min", minutes)
    )
}

fn get_certificate_time(host: &str) -> Result<(String, String, i64, String, String, String), Box<dyn std::error::Error>> {
    let host_parts: Vec<&str> = host.split(":").collect();
    let h: &str = host_parts[0];
    let p: &str = host_parts[1];

    let addr: String = format!("{}:{}", h, p);
    let sock_addr: SocketAddr = addr.to_socket_addrs()?.next().ok_or("[-] No socket address found")?;

    let stream: TcpStream = TcpStream::connect_timeout(&sock_addr, SOCKET_CONNECTION_TIMEOUT)?;
    stream.set_read_timeout(Some(SOCKET_CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_CONNECTION_TIMEOUT))?;
    
    
    // let ip: String = stream.peer_addr()?.to_string().split(":").next().unwrap_or("").to_string();
    let ip: String = stream.peer_addr()?.ip().to_string();
    let connector: TlsConnector = TlsConnector::new()?;
    let stream: native_tls::TlsStream<TcpStream> = connector.connect(h, stream)?;
    let cert: Certificate = stream.peer_certificate()?.ok_or("[-] No certificate found")?;
    let der: Vec<u8> = cert.to_der()?; // Convert certificate to DER format

    // SHA256 Fingerprint
    let mut hasher = sha2::Sha256::new();
    hasher.update(&der);
    let sha256_fingerprint_raw = hasher.finalize();
    let sha256_fingerprint: String = hex::encode_upper(sha256_fingerprint_raw);

    // let sha256_fingerprint = sha256_fingerprint_raw
    //     .iter()
    //     .map(|b| format!("{:02X}", b))
    //     .collect::<Vec<String>>()
    //     .join(":");

    let (_, parsed_cert) = X509Certificate::from_der(&der)?;
    let not_after: i64 = parsed_cert.validity().not_after.timestamp();
    let date: DateTime<Utc> = Utc.timestamp_opt(not_after, 0).single().ok_or("[-] Invalid timestamp")?;
    let time_remaining: chrono::TimeDelta = date.signed_duration_since(Utc::now());
    let days_remaining: i64 = time_remaining.num_days();
    Ok((host.to_string(), ip, days_remaining, format_time_remaining(time_remaining), date.to_string(), sha256_fingerprint))
}



fn check_certificates_all(filename: &str) -> io::Result<()> {
    let file: File = File::open(filename)?;
    let reader: io::BufReader<File> = io::BufReader::new(file);
    let hostnames: Vec<String> = reader.lines().filter_map(Result::ok).collect();

    fs::create_dir_all(format!("output")).expect("[-] Failed to create output directory");

    let mut log_file: Option<Arc<Mutex<fs::File>>> = match fs::File::create(format!("output/log_{}.txt", Utc::now().format("%Y-%m-%d-%H-%M-%S"))) {
        Ok(file) => Some(Arc::new(Mutex::new(file))),
        Err(err) => {
            eprintln!("[-] Failed to create log file: {}", err);
            None
        }
    };
    
    println!("[*] Checking {} endpoints", hostnames.len());
    write_to_file_mutex(&mut log_file, &format!("[*] Checking {} endpoints", hostnames.len()));

    // let results_sorted: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec!["".to_string(); hostnames.len()]));
    // let mut index: usize = 0;

    
    // NORMAL MULTITHREADING
    // let mut handles = vec![];
    // for host in hostnames {
    //     let host_clone: String = host.clone();
    //     // let results_sorted_clone: Arc<Mutex<Vec<String>>> = Arc::clone(&results_sorted);
    //     let handle = thread::spawn(move || {
    //         match get_certificate_time(&host_clone) {
    //             Ok((host, ip, days_remaining, time_remaining_txt, date, sha256fingerprint)) => {
    //                 let status: String = if days_remaining < DAYS_THRESHOLD { "WARN".to_string() } else { "OK".to_string() };
    //                 let line: String = format!("{} {} {} {} {} {}", host, ip, sha256fingerprint, status, time_remaining_txt, date);
    //                 // let mut arr: std::sync::MutexGuard<'_, Vec<String>> = results_sorted_clone.lock().unwrap();
    //                 println!("{}", line);
    //                 // arr[index] = line.clone();
    //                 Some(line)
    //             }
    //             Err(err) => {
    //                 let line: String = format!("{} ERROR: {:?}", host, err);
    //                 // let mut arr: std::sync::MutexGuard<'_, Vec<String>> = results_sorted_clone.lock().unwrap();
    //                 println!("{}", line);
    //                 // arr[index] = line.clone();
    //                 Some(line)
    //             }
    //         }
    //     });
    //     handles.push(handle);
    //     // index += 1;
    // }


    // FOR PROGRESS
    // let total: usize = hostnames.len();
    // let counter: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

    let bar: Arc<ProgressBar> = Arc::new(ProgressBar::new(hostnames.len() as u64));
    bar.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=> "),
    );


    // RAYON MULTITHREADING
    let pool: rayon::ThreadPool = ThreadPoolBuilder::new()
        .num_threads(THREAD_COUNT)
        .build()
        .unwrap();

    let results: Vec<String> = pool.install(|| { hostnames
        .par_iter()
        .map(|host| {
            let result: String = match get_certificate_time(host) {
                Ok((host, ip, days_remaining, time_remaining_txt, date, sha256fingerprint)) => {
                    let status: String = if days_remaining < DAYS_THRESHOLD { "WARN".to_string() } else { "OK".to_string() };
                    let line: String = format!("{} {} {} {} {} {}", host, ip, sha256fingerprint, status, time_remaining_txt, date);
                    // println!("{}", line);
                    line
                }
                Err(err) => {
                    let line: String = format!("{} ERROR: {:?}", host, err);
                    // println!("{}", line);
                    line
                }
            };

            // Update progress
            // let completed: usize = counter.fetch_add(1, Ordering::SeqCst) + 1;
            // println!("[{}/{}] {}", completed, total, host);

            bar.inc(1);

            result
        })
        .collect()
    });
    
    println!("{}", "#".repeat(100));
    println!("[*] Results as completed");

    // NORMAL MULTITHREADING
    // for handle in handles {
    //     match handle.join() {
    //         Ok(Some(line)) => {
    //             println!("{}", line);
    //             write_to_file_mutex(&mut log_file, &line);
    //         }
    //         Ok(None) => {
    //             // Log or record silent failure
    //             let msg: &'static str = "[-] Task finished with no result";
    //             eprintln!("{}", msg);
    //             write_to_file_mutex(&mut log_file, msg);
    //         }
    //         Err(e) => {
    //             // Join panicked thread
    //             eprintln!("[-] Thread panicked: {:?}", e);
    //         }
    //     }
    // }

    for line in &results {
        println!("{}", line);
        write_to_file_mutex(&mut log_file, line);
    }
    



    // // results sorted
    // println!("{}", "#".repeat(100));
    // println!("[*] Results sorted");
    // let results_sorted: Vec<String> = match Arc::try_unwrap(results_sorted) {
    //     Ok(mutex) => match mutex.into_inner() {
    //         Ok(vec) => vec,
    //         Err(e) => {
    //             eprintln!("Failed to unlock mutex: {e}");
    //             return Ok(());
    //         }
    //     },
    //     Err(_) => {
    //         eprintln!("Failed to unwrap Arc: Multiple references exist");
    //         return Ok(());
    //     }
    // };

    // for result in results_sorted {
    //     println!("{}", result);
    //     write_to_file_mutex(&mut log_file, &format!("{}", result));
    // }
    
    Ok(())
}

fn write_to_file_mutex(file: &mut Option<Arc<Mutex<fs::File>>>, content: &str) {
    match file {
        Some(file_arc) => match file_arc.lock() {
            Ok(mut file) => match writeln!(file, "{}", content) {
                Ok(_) => {} // Successfully wrote to file
                Err(e) => eprintln!("[-] Failed to write to file: {}", e),
            },
            Err(e) => eprintln!("[-] Failed to acquire file lock: {}", e),
        },
        None => eprintln!("[-] File not available for writing."),
    }
}
fn main() {
    let start: Instant = Instant::now();
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        let filename: &String = &args[1];
        if let Err(err) = check_certificates_all(filename) {
            eprintln!("[-] Error: {}", err);
        }
    } else {
        println!("[*] Usage: {} [hostnames_file]", args[0]);
    }
    println!("\n[*] Done in {:.2?}", start.elapsed());
}
