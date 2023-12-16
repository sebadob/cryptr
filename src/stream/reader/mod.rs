use crate::stream::reader::file_reader::FileReader;
use crate::stream::reader::memory_reader::MemoryReader;

pub mod file_reader;
pub mod memory_reader;
#[cfg(feature = "s3")]
pub mod s3_reader;

#[derive(Debug)]
pub enum StreamReader<'a> {
    Memory(MemoryReader),
    File(FileReader<'a>),
    #[cfg(feature = "s3")]
    S3(crate::stream::reader::s3_reader::S3Reader<'a>),
}
