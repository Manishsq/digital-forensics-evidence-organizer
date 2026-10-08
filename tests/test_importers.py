"""
Tests for forensic tool output importers.
"""

import pytest


def test_json_importer_single_record():
    from app.importers.json_importer import JSONImporter
    content = '{"filename":"disk.dd","sha256":"abc123","size":1024,"timestamp":"2026-01-01T00:00:00Z"}'
    records = JSONImporter().parse(content)
    assert len(records) == 1
    assert records[0].filename == "disk.dd"
    assert records[0].sha256 == "abc123"
    assert records[0].file_size == 1024


def test_json_importer_list():
    from app.importers.json_importer import JSONImporter
    content = '[{"filename":"a.bin","md5":"aaa"},{"filename":"b.bin","md5":"bbb"}]'
    records = JSONImporter().parse(content)
    assert len(records) == 2
    assert records[0].filename == "a.bin"
    assert records[1].md5 == "bbb"


def test_json_importer_extra_metadata():
    from app.importers.json_importer import JSONImporter
    content = '{"filename":"test.bin","sha256":"def456","tool":"FTK Imager","case_number":"2026-001"}'
    records = JSONImporter().parse(content)
    assert records[0].extra_metadata.get("tool") == "FTK Imager"
    assert records[0].extra_metadata.get("case_number") == "2026-001"


def test_json_importer_invalid_json():
    from app.importers.json_importer import JSONImporter
    with pytest.raises(ValueError, match="Invalid JSON"):
        JSONImporter().parse("{broken json}")


def test_json_can_handle():
    from app.importers.json_importer import JSONImporter
    imp = JSONImporter()
    assert imp.can_handle("output.json")
    assert not imp.can_handle("output.csv")


def test_csv_importer():
    from app.importers.csv_importer import CSVImporter
    content = "filename,sha256,md5,size\ndisk.dd,abc123,def456,1073741824"
    records = CSVImporter().parse(content)
    assert len(records) == 1
    assert records[0].filename == "disk.dd"
    assert records[0].sha256 == "abc123"
    assert records[0].file_size == 1073741824


def test_csv_importer_multiple_rows():
    from app.importers.csv_importer import CSVImporter
    content = "filename,md5\nfile1.bin,aaa\nfile2.bin,bbb\nfile3.bin,ccc"
    records = CSVImporter().parse(content)
    assert len(records) == 3


def test_text_importer_single_block():
    from app.importers.text_importer import TextImporter
    content = "filename: suspect_disk.dd\nsha256: abc123\nsize: 512000\nsource: lab"
    records = TextImporter().parse(content)
    assert len(records) == 1
    assert records[0].filename == "suspect_disk.dd"
    assert records[0].sha256 == "abc123"
    assert records[0].file_size == 512000
    assert records[0].source == "lab"


def test_text_importer_multiple_blocks():
    from app.importers.text_importer import TextImporter
    content = (
        "filename: file1.bin\nsha256: hash1\n\n"
        "filename: file2.bin\nsha256: hash2"
    )
    records = TextImporter().parse(content)
    assert len(records) == 2
    assert records[0].filename == "file1.bin"
    assert records[1].sha256 == "hash2"


def test_text_importer_key_value_equals():
    from app.importers.text_importer import TextImporter
    content = "filename = evidence.pcap\nsha256 = deadbeef\n"
    records = TextImporter().parse(content)
    assert len(records) == 1
    assert records[0].filename == "evidence.pcap"
