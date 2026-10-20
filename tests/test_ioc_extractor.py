"""Unit tests for the IOC extractor."""

from soc_analyst.services.ioc_extractor import IOCOxtractor


def test_extract_ips():
    log_text = "Failed login from 192.168.1.50 and 8.8.8.8. Ignore 127.0.0.1 or 999.999.999.999."
    ips = IOCOxtractor.extract_ips(log_text)
    assert "192.168.1.50" in ips
    assert "8.8.8.8" in ips
    assert "127.0.0.1" not in ips
    assert "999.999.999.999" not in ips
    assert len(ips) == 2


def test_extract_hashes():
    log_text = (
        "MD5: 85e054c5e3d9e0ff5b8e9196b6d5108b, "
        "SHA1: a94a8fe5ccb19ba61c4c0873d391e987982fbbd3, "
        "SHA256: d2c3e1e5b8d23485d34526d1d2345d2d23cde23c1d2e3f4a5b6c7d8e9f0a1b2c"
    )
    hashes = IOCOxtractor.extract_hashes(log_text)
    assert "85e054c5e3d9e0ff5b8e9196b6d5108b" in hashes
    assert "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" in hashes
    assert "d2c3e1e5b8d23485d34526d1d2345d2d23cde23c1d2e3f4a5b6c7d8e9f0a1b2c" in hashes
    assert len(hashes) == 3


def test_extract_urls_and_domains():
    log_text = "Downloaded payload from http://malicious.example.com/c2/payload.exe. Target server is google.com."
    urls = IOCOxtractor.extract_urls(log_text)
    domains = IOCOxtractor.extract_domains(log_text)

    assert "http://malicious.example.com/c2/payload.exe" in urls
    assert "google.com" in domains
    # malicious.example.com shouldn't be matched as standalone domain if filtered, or if it is it's ok,
    # but payload.exe should be filtered out from domains
    assert "payload.exe" not in domains
    assert "vssadmin.exe" not in domains


def test_extract_filenames():
    log_text = "Executed powershell.exe, downloaded evil.exe and loaded badfile.dll."
    filenames = IOCOxtractor.extract_filenames(log_text)
    assert "powershell.exe" in filenames
    assert "evil.exe" in filenames
    assert "badfile.dll" in filenames
    assert len(filenames) == 3


def test_extract_all():
    log_text = "IP 10.0.0.1 executed malware.exe downloading from http://c2.example/payload. MD5: 85e054c5e3d9e0ff5b8e9196b6d5108b"
    res = IOCOxtractor.extract_all(log_text)
    assert "10.0.0.1" in res["ips"]
    assert "malware.exe" in res["filenames"]
    assert "http://c2.example/payload" in res["urls"]
    assert "85e054c5e3d9e0ff5b8e9196b6d5108b" in res["hashes"]
    assert "c2.example" in res["domains"]


def test_extract_unique_list():
    log_text = "Host 10.10.10.10 contacted domain.com with hash 85e054c5e3d9e0ff5b8e9196b6d5108b."
    flat = IOCOxtractor.extract_unique_list(log_text)
    assert len(flat) == 3
    assert "10.10.10.10" in flat
    assert "domain.com" in flat
    assert "85e054c5e3d9e0ff5b8e9196b6d5108b" in flat
