use libsocks_client::SocksClientBuilder;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use anyhow::{Result,anyhow};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::io::AsyncBufReadExt;
use colored::Colorize;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::task::JoinHandle;
use std::process::exit;
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::time::Duration;
use tokio::time::timeout;

static USRPASS: OnceLock<String> = OnceLock::new();

fn init_auth(authstr: &str)
{
    USRPASS.get_or_init(|| String::from(authstr));
}

fn get_auth() -> &'static str {
    USRPASS.get_or_init(|| String::from(""))
}

static DEBUG_OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Debug)]
struct Event {
    target_addr: SocketAddr,
    data: Vec<u8>,
}

fn set_test_case_pass(name: &str)
{
    let okpass = format!("{} OK PASS",name);
    println!("{}",okpass.green());
}

fn set_test_case_failed(name: &str,reason: &str)
{
    let failed = format!("{} ERR:{}",name,reason);
    println!("{}",failed.red());
}

fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

async fn socks4_connect_test(_tx: &tokio::sync::mpsc::Sender<Event>, serverip:&str, serverport:u16, proxyip:&str, proxyport:u16) -> Result<()>
{
    let data = b"socks4_connect_test\n";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks4().build_tcp_client();
    let mut stream = client.connect(serverip, serverport).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4_connect_test connect to {}:{} success!",serverip,serverport);
    }    
    stream.write_all(data).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4_connect_test write data len:{} to {}:{} success!",data.len(),serverip,serverport);
    }    
    let mut buf = vec![0;128];
    let len = stream.read(&mut buf[..]).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4_connect_test read data len {} from {}:{} success!",len,serverip,serverport);
    }     
    if buf[..len].eq(data) { Ok(()) } else { Err(anyhow!("socks4_connect_test data not equal")) }
}

async fn socks4a_connect_test(_tx: &tokio::sync::mpsc::Sender<Event>, serverip:&str, serverport:u16, proxyip:&str, proxyport:u16) -> Result<()>
{
    let data = b"socks4a_connect_test\n";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks4a().build_tcp_client();
    let mut stream = client.connect(serverip, serverport).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4a_connect_test connect to {}:{} success!",serverip,serverport);
    }     
    stream.write_all(data).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4a_connect_test write data len:{} to {}:{} success!",data.len(),serverip,serverport);
    }    
    let mut buf = vec![0;128];
    let len = stream.read(&mut buf[..]).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4a_connect_test read data len {} from {}:{} success!",len,serverip,serverport);
    }     
    if buf[..len].eq(data) { Ok(()) } else { Err(anyhow!("socks4a_connect_test data not equal")) }
}

async fn socks5_connect_test(_tx: &tokio::sync::mpsc::Sender<Event>, serverip:&str, serverport:u16, proxyip:&str, proxyport:u16) -> Result<()>
{
    let data = b"socks5_connect_test\n";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks5().build_tcp_client();
    let mut stream = client.connect(serverip, serverport).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_connect_test connect to {}:{} success!",serverip,serverport);
    }     
    stream.write_all(data).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_connect_test write data len:{} to {}:{} success!",data.len(),serverip,serverport);
    }     
    let mut buf = vec![0;128];
    let len = stream.read(&mut buf[..]).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_connect_test read data len {} from {}:{} success!",len,serverip,serverport);
    }    
    if buf[..len].eq(data) { Ok(()) } else { Err(anyhow!("socks5_connect_test data not equal")) }
}


async fn socks5_auth_connect_test(_tx: &tokio::sync::mpsc::Sender<Event>, serverip:&str, serverport:u16, proxyip:&str, proxyport:u16) -> Result<()>
{
    let data = b"socks5_auth_connect_test\n";
    let auth = get_auth();
    let mut authinfo = auth.split(':');
    let username = authinfo.next().unwrap_or_default();
    let password = authinfo.next().unwrap_or_default();
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks5().username(username).password(password).build_tcp_client();
    let mut stream = client.connect(serverip, serverport).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_auth_connect_test connect to {}:{} success!",serverip,serverport);
    }     
    stream.write_all(data).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_auth_connect_test write data len:{} to {}:{} success!",data.len(),serverip,serverport);
    }     
    let mut buf = vec![0;128];
    let len = stream.read(&mut buf[..]).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_auth_connect_test read data len {} from {}:{} success!",len,serverip,serverport);
    }    
    if buf[..len].eq(data) { Ok(()) } else { Err(anyhow!("socks5_auth_connect_test data not equal")) }
}

async fn socks4a_connect_hostname_test(_tx: &tokio::sync::mpsc::Sender<Event>, _serverip:&str,_serverport:u16, proxyip:&str, proxyport:u16) -> Result<()>
{
    const HTTP_REQUEST: &str = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks4a().build_tcp_client();
    let mut stream = client.connect("www.baidu.com", 80).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4a_connect_hostname_test connect to {}:{} success!","www.baidu.com",80);
    }    
    stream.write_all(&HTTP_REQUEST.as_bytes()).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4a_connect_hostname_test write data len:{} to {}:{} success!",HTTP_REQUEST.len(),"www.baidu.com",80);
    }     
    let mut buf = vec![0; 1024];
    let mut response_buffer = vec![];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response_buffer.extend(&buf[..n]);
    }
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4a_connect_hostname_test read data len {} from {}:{} success!",buf.len(),"www.baidu.com",80);
    }
    if response_buffer.starts_with("HTTP/1.".as_bytes()) { Ok(()) } else { Err(anyhow!("socks4a_connect_hostname_test data not equal")) }
}

async fn socks5_connect_hostname_test(_tx: &tokio::sync::mpsc::Sender<Event>, _serverip:&str, _serverport:u16, proxyip:&str, proxyport:u16) -> Result<()>
{
    const HTTP_REQUEST: &str = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks5().build_tcp_client();
    let mut stream = client.connect("www.baidu.com", 80).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_connect_hostname_test connect to {}:{} success!","www.baidu.com",80);
    }    
    stream.write_all(&HTTP_REQUEST.as_bytes()).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_connect_hostname_test write data len:{} to {}:{} success!",HTTP_REQUEST.len(),"www.baidu.com",80);
    }     
    let mut buf = vec![0; 1024];
    let mut response_buffer = vec![];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response_buffer.extend(&buf[..n]);
    }
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_connect_hostname_test read data len {} from {}:{} success!",buf.len(),"www.baidu.com",80);
    }    
    if response_buffer.starts_with("HTTP/1.".as_bytes()) { Ok(()) } else { Err(anyhow!("socks5_connect_hostname_test data not equal")) }
}

async fn socks4_bind_test(tx: &tokio::sync::mpsc::Sender<Event>,_serverip:&str, _serverport:u16, proxyip:&str, proxyport:u16) -> Result<()>
{
    let data = b"socks4_bind_test\n";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks4().build_listen_client();
    client.bind("0.0.0.0", 0).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4_bind_test bind success!");
    }    
    let addr = client.get_proxy_bind_addr().ok_or(anyhow!("get bind addr failed"))?;
    let event = Event{target_addr: addr,data: data.to_vec()};
    tx.send(event).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4_bind_test bind notify {} success!",addr.to_string());
    }     
    let mut stream = client.accept().await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4_bind_test accept success!");
    }     
    let mut buf = vec![0;128];
    let len = stream.read(&mut buf[..]).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks4_bind_test read len {} success!",len);
    }    
    if buf[..len].eq(data) { Ok(()) }  else { Err(anyhow!("socks4_bind_test data not equal")) }
}

async fn socks5_bind_test(tx: &tokio::sync::mpsc::Sender<Event>, serverip:&str, serverport:u16, proxyip:&str, proxyport:u16) -> Result<()>
{
    let data = b"socks5_bind_test\n";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks5().build_listen_client();
    client.bind(serverip, serverport).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_bind_test bind success!");
    }    
    let addr = client.get_proxy_bind_addr().ok_or(anyhow!("get bind addr failed"))?;
    let event = Event{target_addr: addr,data: data.to_vec()};
    tx.send(event).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_bind_test bind notify {} success!",addr.to_string());
    }    
    let mut stream = client.accept().await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_bind_test accept success!");
    }    
    let mut buf = vec![0;128];
    let len = stream.read(&mut buf[..]).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_bind_test read len {} success!",len);
    }    
    if buf[..len].eq(data) { Ok(()) }  else  { Err(anyhow!("socks5_bind_test data not equal")) }
}

async fn socks5_udp_test(_tx: &tokio::sync::mpsc::Sender<Event>, serverip:&str, serverport:u16, proxyip:&str, proxyport:u16) -> Result<()>
{
    const UDP_DATA: &str = "UDP Data";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks5().build_udp_client();
    client.udp_associate("0.0.0.0", 0).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_udp_test udp_associate success!");
    }     
    let mut udp = client.get_udp_socket("0.0.0.0:0").await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_udp_test get_udp_socket {:?} success!",udp.get_proxy_udp_addr());
    }      
    udp.send_udp_data(UDP_DATA.as_bytes(), &format!("{}:{}",serverip,serverport)).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_udp_test send_udp_data len {} success!",UDP_DATA.len());
    }     
    let data = udp.recv_udp_data(5).await?;
    if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
    {
        println!("socks5_udp_test recv_udp_data len {} success!",data.1.len());
    }    
    if data.1.eq(UDP_DATA.as_bytes()) { Ok(()) } else { Err(anyhow!("socks5_udp_test data not equal")) }
}

async fn run_socks_case<'a,F,S>(name:&str,tx: &'a tokio::sync::mpsc::Sender<Event>, serverip:&'static str, serverport:u16, proxyip: &'static str, proxyport:u16,run_case:F) -> Result<()>
where
    F: Fn(&'a tokio::sync::mpsc::Sender<Event>,&'static str, u16, &'static str, u16) -> S,
    F: Copy + Send + Sync + 'static,
    S: std::future::Future<Output = Result<()>> + Send + 'a,
{
    let r = run_case(tx,serverip,serverport,proxyip,proxyport).await;
    if r.is_ok()
    {
        set_test_case_pass(name);
    }
    else 
    {
        set_test_case_failed(name,&r.err().unwrap().to_string());
    }
    Ok(())
}

async fn run_test_cace_client(tx: &tokio::sync::mpsc::Sender<Event>, case_name: &'static str,serverip:&'static str, serverport:u16, proxyip: &'static str, proxyport:u16)
{
    match case_name {
        "socks4_connect" => {
            _ = run_socks_case(case_name,tx,serverip,serverport,proxyip,proxyport,socks4_connect_test).await;
        }
        "socks5_connect" => {
            _ = run_socks_case(case_name,tx,serverip,serverport,proxyip,proxyport,socks5_connect_test).await;
        }
        "socks4a_connect" => {
            _ = run_socks_case(case_name,tx,serverip,serverport,proxyip,proxyport,socks4a_connect_test).await;
        }
        "socks4a_connect_hostname" => {
            _ = run_socks_case(case_name,tx,serverip,serverport,proxyip,proxyport,socks4a_connect_hostname_test).await;
        }
        "socks5_connect_hostname" => {
            _ = run_socks_case(case_name,tx,serverip,serverport,proxyip,proxyport,socks5_connect_hostname_test).await;
        }
        "socks5_auth_connect" => {
            _ = run_socks_case(case_name,tx,serverip,serverport,proxyip,proxyport,socks5_auth_connect_test).await;
        }        
        "socks4_bind" => {
            _ = run_socks_case(case_name,tx,serverip,serverport,proxyip,proxyport,socks4_bind_test).await;
        }
        "socks5_bind" => {
            _ = run_socks_case(case_name,tx,serverip,serverport,proxyip,proxyport,socks5_bind_test).await;
        }
        "socks5_udp" => {
            _ = run_socks_case(case_name,tx,serverip,serverport,proxyip,proxyport,socks5_udp_test).await;
        }
        _ => {

        }                       
    }
}

async fn  run_udp_echo_server(ip: &str, port: u16) -> Result<()>
{
    let sock = UdpSocket::bind(format!("{}:{}",ip,port)).await?;
    let mut buf = [0; 1024];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        let _len = sock.send_to(&buf[..len], addr).await?;
    }
}
async fn run_tcp_bind_server(rx: &mut tokio::sync::mpsc::Receiver<Event>) -> Result<()>
{
    while let Some(event) = rx.recv().await {
        if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
        {
            println!("run_tcp_bind_server received event success!");
        }        
        match timeout(Duration::from_secs(5), TcpStream::connect(&event.target_addr)).await{
            Ok(result) => {
                match result {
                    Ok(mut stream) => {
                        if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            println!("run_tcp_bind_server connect {:?} success!",event.target_addr);
                        }        
                        stream.write_all(&event.data).await?;
                        if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            println!("run_tcp_bind_server send data success!");
                        }
                        let _x = stream.shutdown().await;
                    },
                    Err(_err) => return Err(anyhow!("tcp connect failed")),
                }
            },
            Err(_err) => return Err(anyhow!("tcp connect timeout")),
        }
    }
    Ok(())
}

async fn run_tcp_echo_server(ip: &str, port: u16) -> Result<()>
{
    let addr = format!("{}:{}",ip,port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    loop
    {
        match listener.accept().await {
            Ok((mut socket, _addr)) => {
                tokio::spawn(async move {
                    let (reader, mut writer) = socket.split();
                    let mut reader = tokio::io::BufReader::new(reader);
                    let mut msg: String = String::new();
                    loop {
                        match reader.read_line(&mut msg).await {
                            Ok(_bytes_size) => {
                                match writer.write_all(&msg.as_bytes()).await {
                                    Ok(()) => (),
                                    Err(err) => { print!("Err:{:?}",err); }
                                }
                                let _x = writer.shutdown();
                                break;             
                            }
                            Err(err) => { print!("Err:{:?}",err); }
                        }
                    }
                });
            }
            Err(err) => {print!("Err:{:?}",err)}
        }
    }
}


fn parse_args() -> clap::ArgMatches
{
    let matches = clap::Command::new("sockstest")
    .arg_required_else_help(true)
    .version("1.0")
    .arg(clap::Arg::new("proxyip")
        .long("proxyip")
        .value_name("ipaddress")
        .help("set proxy ipaddress")
        .required(true))
    .arg(clap::Arg::new("proxyport")
        .long("proxyport")
        .value_name("port")
        .help("set proxy port")
        .required(true))
    .arg(clap::Arg::new("serverip")
        .long("serverip")
        .value_name("ipaddress")
        .help("set proxy test running host ipaddress,default use 0.0.0.0")
        .required(true))
    .arg(clap::Arg::new("serverport")
        .long("serverport")
        .value_name("port")
        .help("set proxy test running host port,default use 3307")
        .required(false)
        .default_value("3307"))    
    .arg(clap::Arg::new("auth")
        .long("auth")
        .value_name("auth")
        .help("set socks username and password,split with :")
        .required(false)
        .default_value(""))
    .arg(clap::Arg::new("casename")
        .long("casename")
        .value_name("test case name")
        .next_line_help(true)
        .value_parser(["socks4_connect","socks5_connect","socks5_connect_hostname","socks4a_connect_hostname","socks4a_connect",
        "socks4_bind","socks5_bind","socks5_udp","socks5_auth_connect","socks5_auth_bind","socks5_auth_udp"])
        .hide_possible_values(false)
        .required(true))
    .arg(clap::Arg::new("debug")
        .long("debug")
        .num_args(0)
        .action(clap::ArgAction::SetTrue)
        .help("print debug message")
        .required(false))
    .get_matches();
    matches
}

#[tokio::main]
async fn main() -> Result<()>{

    let (tx, mut rx) = mpsc::channel::<Event>(100);

    let matches = parse_args();

    let proxyip = matches.get_one::<String>("proxyip").expect("proxyip").clone();
    let proxyipstr: &str = string_to_static_str(proxyip);

    let proxyport = matches.get_one::<String>("proxyport").expect("proxyport").clone();
    let proxyportint = proxyport.parse::<u16>().unwrap();


    let serverip = matches.get_one::<String>("serverip").expect("serverip").clone();
    let serveripstr: &str = string_to_static_str(serverip);

    let serverport = matches.get_one::<String>("serverport").expect("serverport").clone();
    let serverportint = serverport.parse::<u16>().unwrap();

    let authinfo = matches.get_one::<String>("auth").expect("auth").clone();
    init_auth(&authinfo);

    let debug: bool = matches.get_flag("debug");
    if debug
    {
        DEBUG_OPEN.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    let casename = matches.get_one::<String>("casename").expect("casename").clone();
    
    let casenamestr: &str = string_to_static_str(casename);

    let mut v = vec![];
    let mut set = JoinSet::new();
    let service_bind_server: JoinHandle<Result<()>> = tokio::task::spawn(
        async move {
            _ = run_tcp_bind_server(&mut rx).await;
            exit(1);
        }
    );
    let service_udp_server: JoinHandle<Result<()>> = tokio::task::spawn(
        async move {
            _ =  run_udp_echo_server(&serveripstr,serverportint).await;
            exit(1);
        }
    );
    let service_tcp_server:  JoinHandle<Result<()>> = tokio::task::spawn(
        async move {
            _ = run_tcp_echo_server(&serveripstr,serverportint).await;
            exit(1);
        }
    );
    let case_run: JoinHandle<Result<()>>  = tokio::task::spawn(
        async move {
            run_test_cace_client(&tx,casenamestr,&serveripstr,serverportint,&proxyipstr,proxyportint).await;
            exit(0);
        }
    );

    v.push(service_bind_server);
    v.push(service_udp_server);
    v.push(service_tcp_server);
    v.push(case_run);

    for fut in v
    {
        set.spawn(fut);
    }

    while let Some(res) = set.join_next().await{
        println!("{:?}",res);
    }

    Ok(())
}
