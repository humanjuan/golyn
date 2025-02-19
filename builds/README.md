# `builds` Directory

This directory contains scripts to compile, package, and prepare the Golyn server for deployment across multiple platforms. Each script generates a release package specific to the target operating system, ensuring portability and readiness for deployment.

The `builds` directory provides scripts to build the Golyn server for the following platforms:
- **Linux**
- **macOS**
- **Windows**

Each platform-specific script creates a release package that contains:
- The compiled server binary for the respective platform.
- Directory structure including configuration files, SSL/TLS certificates, log directories, and other necessary assets.
- A release note file containing metadata such as file names, last updates, and hash information.
- Packaged output in `.tar.gz` or `.zip` format, depending on the platform.

---

## Requirements

Before running the build scripts, ensure the following dependencies are installed:

- **Go Compiler** (minimum version 1.16)
- **Bash Shell**
- **gsed** (GNU Sed – for macOS and Linux)
- **GNU tar** or **bsdtar** (for packaging)
- **Windows Subsystem for Linux (WSL)** or a similar shell environment (for executing Bash scripts on Windows)

---

## Usage

Navigate to the `builds` directory and execute the relevant script for your target platform. The details for each platform are as follows:

### Linux

To build and package the Golyn server for Linux:

```bash
cd builds
./build-linux.sh
```

The resulting package will be available as a `.tar.gz` file in the `builds/` directory.

---

### macOS

To build and package the Golyn server for macOS:

```bash
cd builds
./build-macos.sh
```

The resulting package will also be available as a `.tar.gz` file in the `builds/` directory.

---

### Windows

To build and package the Golyn server for Windows:

```bash
cd builds
./build-windows.sh
```

The resulting package will be available as a `.zip` file in the `builds/` directory.

---

## Output Structure

After successfully running a build script, the package will follow the structure below:

```plaintext
builds/
├── Golyn/                   # Main release directory
│   ├── golyn                # Compiled binary for the target platform
│   ├── config/              # Configuration files
│   ├── certificates/        # SSL/TLS certificates
│   ├── var/
│   │   └── log/             # Logs directory
│   ├── sites/               # Static site assets (e.g., Golyn-related files)
│   └── Golyn_release_note.txt # Release note with file metadata and hashes
```

---

## Script Details

### `build-linux.sh`
- **Purpose:** Compiles and creates a release package for the Golyn server targeted for Linux systems.
- **Output File:** A `.tar.gz` package.
- **Dependencies:** Bash, GNU tar, gsed, Go compiler.

### `build-macos.sh`
- **Purpose:** Compiles and creates a release package for the Golyn server targeted for macOS systems.
- **Output File:** A `.tar.gz` package.
- **Dependencies:** Bash, bsdtar, gsed, Go compiler.

### `build-windows.sh`
- **Purpose:** Compiles and creates a release package for the Golyn server targeted for Windows systems.
- **Output File:** A `.zip` package.
- **Dependencies:** Bash, Zip, gsed, Go compiler.

---

## Notes

- Before running the scripts, remove any existing intermediate or old build artifacts from the `builds/` directory to avoid conflicts.
- The scripts automatically create a release note file that lists all files in the package along with their last update timestamps and MD5 hashes.
- Ensure that the Go compiler is installed and configured correctly within your environment before executing the scripts.
- For Windows builds, make sure WSL or another Bash-like environment is properly set up on the system.
- If there are errors during compilation or packaging, check the dependencies and logs for troubleshooting.

---