extern crate chrono;
extern crate fern;
extern crate ipnetwork;
extern crate rand;
extern crate threadpool;
extern crate url;

use ipnetwork::IpNetwork;
use rand::seq::SliceRandom;
use rand::Rng;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use url::Url;
use csv::Writer;
use std::cmp::Ordering; // 排序
use std::collections::HashSet;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use threadpool::ThreadPool;

const TCP_PAYLOAD: &[u8] = b"\x16\x03\x01\x01\x12\x01\x00\x01\x0e\x03\x03\xcb\xb5\xb7\x93\xd5\x37\x68\x6f\x97\x6c\x7c\x84\x6c\x81\x3f\xcd\x32\x0a\x08\xd2\x54\x00\x3b\x9d\x18\xe5\x0b\x13\xd1\xf3\x97\x61\x20\x2a\x13\x58\xce\xd5\xc5\xc3\xd5\xbc\xc9\x07\x87\x8e\xe8\x74\x47\x89\xe5\xd9\x2c\x4e\xe9\x68\x43\xa1\x18\x2a\xab\xd3\x5c\x6f\x01\x00\x26\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x09\xc0\x13\xc0\x0a\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\xc0\x12\x00\x0a\x13\x01\x13\x02\x13\x03\x01\x00\x00\x9f\x00\x00\x00\x11\x00\x0f\x00\x00\x0c\x76\x32\x2e\x68\x6f\x61\x69\x2e\x6c\x69\x6e\x6b\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x0d\x00\x1a\x00\x18\x08\x04\x04\x03\x08\x07\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x05\x03\x06\x03\x02\x01\x02\x03\xff\x01\x00\x01\x00\x00\x17\x00\x00\x00\x10\x00\x0b\x00\x09\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x12\x00\x00\x00\x2b\x00\x05\x04\x03\x04\x03\x03\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x7d\xaa\x99\x07\x71\x4e\x47\xd3\x61\x0a\xb5\x1d\x83\x86\xec\xd6\x7f\x16\x52\xa4\xf7\xb5\x31\xaa\x50\x93\xa1\x82\x9e\xad\x94\x08";

// 初始化日志（设置日志格式）
fn init_logger() -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} {:<5}{}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Info)
        .chain(io::stdout())
        .apply()?;
    Ok(())
}

// 检查curl是否已经在电脑中安装好
fn is_curl_installed() -> bool {
    let output = Command::new("curl").arg("--version").output().is_ok(); // 检查命令执行是否成功

    output
}

// 使用CURL命令（需要在电脑中安装curl才能使用，特别是windows系统中），判断headers头文件信息是否有cloudflare字符
fn check_server_is_cloudflare(ip: &str) -> Result<(String, bool), io::Error> {
    let formatted_ip = if let Ok(ip_network) = ip.parse::<IpNetwork>() {
        if ip_network.is_ipv6() {
            format!("[{}]", ip)
        } else {
            ip_network.ip().to_string()
        }
    } else {
        let trimmed_ip = if ip.ends_with('/') {
            // 用于去掉右侧"/"的字符
            ip.trim_end_matches('/').to_string()
        } else {
            ip.to_string()
        };
        trimmed_ip
    };
    let host_name = if formatted_ip.starts_with("http://") || formatted_ip.starts_with("https://") {
        let url_parse = Url::parse(&formatted_ip).unwrap(); // 解析URL
        let domain = url_parse.host_str().unwrap_or_default().to_string(); // 提取域名
        domain
    } else {
        formatted_ip
    };
    let url = format!("http://{}/cdn-cgi/trace", host_name);

    for _ in 0..3 {
        let curl_process = Command::new("curl")
            .arg("/dev/null")
            .arg("-I")
            .arg(url.clone())
            .arg("-s")
            .arg("-m")
            .arg("10") // 设置超时(单位：秒)
            .stdout(Stdio::piped())
            .spawn();

        // 检查curl进程是否成功启动
        match curl_process {
            Ok(child) => {
                let output = child.wait_with_output()?; // 等待子进程完成
                let stdout = String::from_utf8_lossy(&output.stdout);
                // 如果curl输出中，server参数中是"cloudflare"
                if let Some(server_header) = extract_server_header(&stdout) {
                    if server_header.contains("cloudflare") {
                        return Ok((host_name.to_string(), true));
                    }
                }
            }
            Err(_) => {}
        }
    }
    return Ok((host_name.to_string(), false));
}

// 提取响应头的server服务器是什么？cloudflare？
fn extract_server_header(curl_output: &str) -> Option<String> {
    let lines: Vec<&str> = curl_output.lines().collect();

    for line in lines {
        if line.starts_with("Server:") {
            // 删除前后的空格并返回值
            return Some(line["Server:".len()..].trim().to_string());
        }
    }

    None
}

// 检查文件读取的地址是IPv4地址、IPv6地址、域名，如果是CIDR，就生成IP地址
fn generate_ip_and_check_ip_type(ip_address: &str) -> Vec<String> {
    // CIDR的处理方案
    if let Ok(ip_network) = ip_address.parse::<IpNetwork>() {
        if ip_network.is_ipv6() {
            if ip_network.prefix() < 119 {
                let mut rng = rand::thread_rng();
                let mut addresses = Vec::new();
                let num_addresses = 500; // 生成最多500个IPv6地址

                let generated_addresses: Vec<Ipv6Addr> =
                    generate_random_ipv6_in_cidr(&ip_network, &mut rng, num_addresses);

                for ip in generated_addresses {
                    addresses.push(ip.to_string());
                }
                return addresses;
            } else {
                // 前缀长度大于等于119，生成CIDR范围内的所有IPv6地址
                let addresses: Vec<String> = ip_network.iter().map(|ip| ip.to_string()).collect();
                return addresses;
            }
        } else {
            return ip_network.iter().map(|ip| ip.to_string()).collect(); // 生成IPv4地址
        }
    }
    // 是IPv4地址、IPv6地址的
    if let Ok(ip) = ip_address.parse::<IpAddr>() {
        return vec![ip.to_string()];
    }

    // 不满足上面的条件，就原字符串返回，默认是域名地址
    vec![ip_address.to_string()]
}

// 生成IPv6 CIDR范围内的随机500个IPv6地址
fn generate_random_ipv6_in_cidr(
    ip_network: &IpNetwork,
    rng: &mut impl Rng,
    num_addresses: usize,
) -> Vec<Ipv6Addr> {
    if let IpNetwork::V6(cidr) = ip_network {
        let lower = u128::from(cidr.network());
        let upper = u128::from(cidr.broadcast());

        if lower <= upper {
            let mut generated_addresses = Vec::with_capacity(num_addresses);
            let mut num_generated = 0;

            while num_generated < num_addresses {
                let random_ipv6_int: u128 = rng.gen_range(lower..=upper);
                let random_ipv6_addr = Ipv6Addr::from(random_ipv6_int);

                // 检查地址是否在CIDR范围内并且不重复
                if !generated_addresses.contains(&random_ipv6_addr) {
                    generated_addresses.push(random_ipv6_addr);
                    num_generated += 1;
                }
            }

            return generated_addresses;
        } else {
            panic!("Invalid CIDR range");
        }
    } else {
        unreachable!();
    }
}

// 按行读取文件的内容
fn read_ips_file(file_path: &str) -> Result<Vec<String>, io::Error> {
    let file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            println!("打开{}文件错误，错误原因是:{}", file_path, e);
            print!("按Enter键退出程序！");
            io::stdout().flush().expect("Failed to flush stdout");
            let _ = io::stdin().read_line(&mut String::new());
            std::process::exit(1);
        }
    };
    let ips: Vec<String> = io::BufReader::new(file)
        .lines()
        .filter_map(|line| line.ok())
        .collect();
    if ips.is_empty() {
        print!("{}文件是空的，按Enter键退出程序！", file_path);
        io::stdout().flush().expect("Failed to flush stdout");
        let _ = io::stdin().read_line(&mut String::new());
        std::process::exit(1);
    }
    Ok(ips)
}

// 定义一个函数，用于与TCP服务器建立连接并发送数据
fn tcp_client_hello(address: &str, port: u16) -> (String, u16, bool, String) {
    // 记录函数开始时间
    let start_time = Instant::now();

    // 构建服务器地址
    let addr = format!("{}:{}", address, port);
    let server_addr: SocketAddr = addr.parse().unwrap();

    // 设置较短的连接超时时间
    let connect_timeout_duration = Duration::from_secs(5);

    // 尝试与服务器建立连接
    match TcpStream::connect_timeout(&server_addr, connect_timeout_duration) {
        Ok(mut stream) => {
            // 设置读取超时时间，等待数据接收
            let read_timeout_duration = Duration::from_secs(5);
            stream
                .set_read_timeout(Some(read_timeout_duration))
                .expect("set_read_timeout 失败");

            // 尝试向服务器写入数据
            if let Err(err) = stream.write_all(TCP_PAYLOAD) {
                log::info!("{}:{}, false, 写入错误: {}", address, port, err);
                return (
                    address.to_string(),
                    port,
                    false,
                    format!("写入错误: {}", err),
                );
            }

            // 准备接收服务器的响应数据
            let mut response = [0; 100];
            if let Err(_err) = stream.read_exact(&mut response) {
                log::info!(
                    "{}:{}, false, 读取错误：连接方在一段时间后没有正确答复或连接的主机没有反应！",
                    address,
                    port
                );
                return (
                    address.to_string(),
                    port,
                    false,
                    format!("读取错误：连接方在一段时间后没有正确答复或连接的主机没有反应！"),
                );
            }

            // 计算经过的时间（毫秒）
            let elapsed_time = start_time.elapsed().as_secs_f64() * 1000.0;
            log::info!(
                "{}:{}, true, 响应时间: {:.2}毫秒",
                address,
                port,
                elapsed_time
            );
            (
                address.to_string(),
                port,
                true,
                format!("{:.2}", elapsed_time),
            )
        }
        Err(_err) => {
            log::info!("{}:{}, false, 连接超时错误！", address, port);
            (address.to_string(), port, false, format!("连接超时错误！"))
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    init_logger()?;
    let ip_addresses = read_ips_file("ips-v4.txt")?;

    if !is_curl_installed() {
        println!("电脑中，没有安装有curl命令！按Enter键退出程序！");
        io::stdout().flush().expect("Failed to flush stdout");
        let _ = io::stdin().read_line(&mut String::new());
        std::process::exit(1);
    }

    // 线程池：生成CIDR范围的IP地址
    let pool_generate = threadpool::ThreadPool::new(20);
    let (tx_generate, rx_generate) = mpsc::channel();

    for item in ip_addresses.iter() {
        let tx_generate = tx_generate.clone();
        let cloned_item = item.clone();
        pool_generate.execute(move || {
            let ips = generate_ip_and_check_ip_type(&cloned_item);
            tx_generate.send(ips).unwrap();
        });
    }

    drop(tx_generate); // 释放发送端。不影响要接受的(rx_generate)信息；同时便于后续迭代

    println!("开始扫描CF CDN中...\n");

    let mut ips: Vec<String> = Vec::new();
    // 从接受端迭代结果放到ips中
    for ips_batch in rx_generate.iter() {
        ips.extend(ips_batch);
    }

    let mut rng = rand::thread_rng();
    ips.shuffle(&mut rng); // 打乱排列顺序

    // 线程池：调用check_server_is_cloudflare函数，获取测试后的结果
    let pool_method = threadpool::ThreadPool::new(200);
    /* mpsc通道，用于在线程之间安全地传递数据，其中一个线程（或多个线程）充当生产者，而另一个线程（单个线程）充当消费者。
       mpsc（多个生产者、单个消费者）通道，创建了两个端点，一个发送端 (tx_method) 和一个接收端 (rx_method)。
       这种通道类型在并发编程中非常有用，因为它提供了一种线程间通信的方式，以避免竞态条件和数据竞争。
    */
    let (tx_method, rx_method) = mpsc::channel();

    for item in ips.iter() {
        let tx_method = tx_method.clone();
        let cloned_item = item.clone();
        pool_method.execute(move || {
            if let Ok((ip, state)) = check_server_is_cloudflare(&cloned_item) {
                log::info!("{}/cdn-cgi/trace --> RESULT: {}", ip, state);
                if state {
                    tx_method.send(ip).unwrap();
                }
            }
        });
    }

    drop(tx_method); // 释放发送端。不影响要接受的(rx_method)信息；同时便于后续迭代

    let mut reachable_ips: Vec<String> = Vec::new();
    // 从接受端迭代结果放到reachable_ips中
    for ip in rx_method.iter() {
        let cleaned_ip = ip.trim_matches(|c| c == '[' || c == ']'); // 去掉IPv6地址的方括号
        reachable_ips.push(cleaned_ip.to_string());
    }

    println!("hello cdn..................................................................");
    let ports = vec![443, 2053, 2083, 2087, 2096, 8443];

    let shuffle_combined_list: Vec<(String, u16)> = reachable_ips
        .iter()
        .flat_map(|ip| ports.iter().map(move |port| (ip.clone(), *port)))
        .collect();
    // 创建一个 HashSet 来存储唯一的元素
    let mut unique_elements: HashSet<(String, u16)> = HashSet::new();

    // 使用迭代器遍历 shuffle_combined_list，并将唯一的元素添加到 HashSet 中
    let deduplicated_list: Vec<(String, u16)> = shuffle_combined_list
        .into_iter()
        .filter(|element| unique_elements.insert(element.clone()))
        .collect();

    // 创建线程池，并指定线程数量
    let pool = ThreadPool::new(200);

    // 创建发送和接收结果的通道（有界通道）
    let (sender, receiver) = mpsc::channel();

    for (ip, port) in deduplicated_list {
        let sender_clone = sender.clone();
        pool.execute(move || {
            let result = tcp_client_hello(&ip, port);
            sender_clone.send(result).expect("Send error");
        });
    }

    drop(sender); // 丢弃发送端，表示不再发送数据

    // 从线程中收集结果
    let mut received_results = Vec::new();
    for received_result in receiver {
        if received_result.2 {
            // 检查 received_result 的第三个元素是否为 true
            received_results.push(received_result); // 将 true 结果添加到向量中
        }
    }

    // 关闭线程池
    pool.join();

    // 创建一个向量用于存储 true 的结果
    let mut true_results: Vec<_> = received_results.iter().filter(|result| result.2).collect();

    // 排序 true_results 按照第三列 elapsed_time 的升序排列
    true_results.sort_by(|a, b| {
        let elapsed_time_a = a.3.parse::<f64>().unwrap_or(f64::MAX);
        let elapsed_time_b = b.3.parse::<f64>().unwrap_or(f64::MAX);

        elapsed_time_a
            .partial_cmp(&elapsed_time_b)
            .unwrap_or(Ordering::Equal)
    });

    if !true_results.is_empty() {
        // 定义基础文件名
        let base_file_name = "results.csv";

        // 确定最终文件名（文件存在时，使用这个添加序号的文件名）
        let final_file_name = find_available_file_name(base_file_name);

        // 创建或打开 CSV 文件
        let file = File::create(&final_file_name).expect("Failed to create file");
        let mut wtr = Writer::from_writer(file);
        wtr.write_record(&["IP", "PORT", "Response Time(ms)"])?; // 首先写入CSV的标题
                                                                 // 将结果写入 CSV 文件
        for (address, port, _, elapsed_time) in &true_results {
            wtr.write_record(&[address, &port.to_string(), elapsed_time])
                .expect("Failed to write record");
        }
        wtr.flush().expect("Failed to flush CSV writer");
        println!("\n结果写入: {}", final_file_name);
    }

    // 排序
    // reachable_ips.sort_by(|ip1, ip2| custom_ip_sort(ip1, ip2));
    // 写入文件中
    // write_to_file(&reachable_ips, "output.txt")?;

    // 记录结束的时间
    let end_time = Instant::now();
    // 计算程序运行的总时长
    let elapsed_duration = end_time.duration_since(start_time);
    // 转换为人类易读的时间
    let (elapsed_time, unit) = format_duration(elapsed_duration);

    print!("\n程序运行结束，耗时：{:.2}{}，", elapsed_time, unit);
    io::stdout().flush().expect("Failed to flush stdout");

    wait_for_enter();

    Ok(())
}

// 用于排序（IPv4、IPv6地址、域名）
fn _custom_ip_sort(ip1: &String, ip2: &String) -> std::cmp::Ordering {
    let parse_result1 = IpAddr::from_str(ip1);
    let parse_result2 = IpAddr::from_str(ip2);

    match (parse_result1, parse_result2) {
        (Ok(ip1), Ok(ip2)) => ip1.cmp(&ip2),
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Err(_), Err(_)) => std::cmp::Ordering::Equal,
    }
}

// 将结果写入文件
fn _write_to_file(data: &[String], file_name: &str) -> Result<(), io::Error> {
    let mut file = File::create(file_name)?;
    for ip in data {
        writeln!(file, "{}", ip)?;
    }
    Ok(())
}

// 计算程序运行的总时长
fn format_duration(duration: Duration) -> (f64, &'static str) {
    if duration.as_secs() > 0 {
        (duration.as_secs_f64(), "秒")
    } else if duration.as_millis() > 0 {
        (duration.as_millis() as f64, "毫秒")
    } else if duration.as_micros() > 0 {
        (duration.as_micros() as f64, "微秒")
    } else {
        (duration.as_nanos() as f64, "纳秒")
    }
}

// 辅助函数
fn wait_for_enter() {
    print!("按Enter键，退出程序！");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
}

// 如果文件存在，就添加序号
fn find_available_file_name(base_name: &str) -> String {
    let mut counter = 1;
    let mut new_base_name = String::from(base_name);

    while Path::new(&new_base_name).exists() {
        let file_extension = Path::new(&new_base_name)
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or("");
        let base_name_without_extension =
            &new_base_name[..new_base_name.len() - file_extension.len() - 1];

        if let Some(index) = base_name_without_extension.rfind('-') {
            let next_number = &base_name_without_extension[index + 1..];
            if let Ok(num) = next_number.parse::<u32>() {
                counter = num + 1;
                new_base_name = format!(
                    "{}-{}.{}",
                    &base_name_without_extension[..index],
                    counter,
                    file_extension
                );
            } else {
                new_base_name = format!(
                    "{}-{}.{}",
                    base_name_without_extension, counter, file_extension
                );
            }
        } else {
            new_base_name = format!(
                "{}-{}.{}",
                base_name_without_extension, counter, file_extension
            );
        }
        counter += 1;
    }

    new_base_name
}
