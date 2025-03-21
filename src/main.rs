use std::{
    env,
    fs::File,
    io::{self, BufReader, Error, Read},
    path::{Path, PathBuf},
};

#[derive(Debug)]
struct PcapGlobalHeader {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

#[derive(Debug)]
struct PcapPacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

#[derive(Debug)]
struct PcapIPv4Header {
    header_len: u8,
    service_type: u8,
    pack_len: u16,
    identification: u16,
    flags_offset: u16,
    time_to_live: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
}

#[derive(Debug)]
struct PcapTCPHeader {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    header_len: u16,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

#[derive(Debug)]
struct PcapPacket {
    pack_header: PcapPacketHeader,
    ipv4_header: PcapIPv4Header,
    tcp_header: PcapTCPHeader,
    data: Vec<u8>,
}

fn log(msg: &str) {
    println!("{}", msg);
}

#[derive(Debug)]
enum Endianess {
    Big,
    Little,
}

struct PcapFileReader {
    reader: BufReader<File>,
    endian: Endianess,
}

impl PcapFileReader {
    fn read_u8(&mut self) -> Result<u8, io::Error> {
        let mut buf = [0; 1];
        self.reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&mut self) -> Result<u16, io::Error> {
        let mut buf = [0; 2];
        self.reader.read_exact(&mut buf)?;
        Ok(match self.endian {
            Endianess::Big => u16::from_be_bytes(buf),
            Endianess::Little => u16::from_le_bytes(buf),
        })
    }

    fn read_u32(&mut self) -> Result<u32, io::Error> {
        let mut buf = [0; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(match self.endian {
            Endianess::Big => u32::from_be_bytes(buf),
            Endianess::Little => u32::from_le_bytes(buf),
        })
    }

    fn read_i32(&mut self) -> Result<i32, io::Error> {
        let mut buf = [0; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(match self.endian {
            Endianess::Big => i32::from_be_bytes(buf),
            Endianess::Little => i32::from_le_bytes(buf),
        })
    }

    fn read_global_header(&mut self) -> Result<PcapGlobalHeader, io::Error> {
        // The magic number has been read during opening, maybe needs rewind
        let version_major = self.read_u16()?;
        let version_minor = self.read_u16()?;
        let thiszone = self.read_i32()?;
        let sigfigs = self.read_u32()?;
        let snaplen = self.read_u32()?;
        let network = self.read_u32()?;

        Ok( PcapGlobalHeader {
            magic_number: match self.endian {
                Endianess::Big => 0xa1b2c3d4,
                Endianess::Little => 0xd4c3b2a1,
            },
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            network,
        })
    }

    fn read_next_packet(&mut self) -> Result<PcapPacket, io::Error> {
        // Hardcode values for early validation
        let HEADER_SIZE = 52;
        let pack_header = PcapPacketHeader {
            ts_sec: self.read_u32()?,
            ts_usec: self.read_u32()?,
            incl_len: self.read_u32()?,
            orig_len: self.read_u32()?,
        };

        let ipv4_header = PcapIPv4Header {
            header_len: self.read_u8()?,
            service_type: self.read_u8()?,
            pack_len: self.read_u16()?,
            identification: self.read_u16()?,
            flags_offset: self.read_u16()?,
            time_to_live: self.read_u8()?,
            protocol: self.read_u8()?,
            checksum: self.read_u16()?,
            src_addr: self.read_u32()?,
            dst_addr: self.read_u32()?,
        };

        let tcp_header = PcapTCPHeader {
            src_port: self.read_u16()?,
            dst_port: self.read_u16()?,
            seq_num: self.read_u32()?,
            ack_num: self.read_u32()?,
            header_len: self.read_u16()?,
            window_size: self.read_u16()?,
            checksum: self.read_u16()?,
            urgent_pointer: self.read_u16()?,
        };

        if pack_header.incl_len <= 40 {
            return Err(Error::new(io::ErrorKind::AddrNotAvailable, "size not match"));
        }

        let pack_len = (pack_header.incl_len - 40) as usize;
        let mut buffer = vec![0; pack_len];
        self.reader.read_exact(&mut buffer)?;

        Ok(PcapPacket {
            pack_header,
            ipv4_header,
            tcp_header,
            data: buffer,
        })
    }
}

fn open_pcap_file(path: &Path) -> Result<PcapFileReader, io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut magic_number = [0; 4];
    reader.read_exact(&mut magic_number)?;

    let magic_number = u32::from_be_bytes(magic_number);
    if magic_number == 0xa1b2c3d4 {
        Ok(PcapFileReader {
            reader,
            endian: Endianess::Big,
        })
    } else if magic_number == 0xd4c3b2a1 {
        Ok(PcapFileReader {
            reader,
            endian: Endianess::Little,
        })
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid magic number",
        ))
    }
}

fn main() {
    let path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("No file path provided");

    let mut reader = open_pcap_file(&path).expect("Failed to open file");
    log(&format!("Opened file: {:?}", path));

    let global_header = reader.read_global_header().expect("Error occurred during parsing global header.");
    log(&format!("Parsed global header {:#?}", global_header));

    while let Ok(packet) = reader.read_next_packet() {
        log(&format!("Read a packet length={:}, ts={:}", packet.pack_header.incl_len - 40, packet.pack_header.ts_sec))
    }

    log(&format!("End reading"));
}
