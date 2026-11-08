namespace BackupViewer.Models;

public enum FileKind
{
    Unknown,
    Directory,
    Empty,
    Missing,
    Text,
    Json,
    Xml,
    PlistXml,
    PlistBinary,
    Sqlite,
    Protobuf,
    Image,
    Video,
    Audio,
    Binary,
}
