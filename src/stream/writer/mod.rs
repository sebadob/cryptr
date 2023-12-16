use crate::stream::writer::file_writer::FileWriter;
use crate::stream::writer::memory_writer::MemoryWriter;

pub mod file_writer;
pub mod memory_writer;
#[cfg(feature = "s3")]
pub mod s3_writer;

#[derive(Debug)]
pub enum StreamWriter<'a> {
    Memory(MemoryWriter<'a>),
    File(FileWriter<'a>),
    #[cfg(feature = "s3")]
    S3(crate::stream::writer::s3_writer::S3Writer<'a>),
}
