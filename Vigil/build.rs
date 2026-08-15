fn main() {
    let mut res = winres::WindowsResource::new();
    res.set("ProductName", "RYFTENIUS Vigil");
    res.set("FileDescription", "RYFTENIUS Vigil");
    res.set("CompanyName", "RYFTENIUS");
    res.set_manifest_file("windows/vigil.manifest");
    res.compile().unwrap();
}
