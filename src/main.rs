fn main() {
    std::process::exit(archive_structure_check::cli::run(std::env::args().skip(1)));
}
