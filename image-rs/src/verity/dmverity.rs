// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Error, Result};
use base64::Engine;
use devicemapper::{DevId, DmFlags, DmName, DmOptions, DM};
use serde::{Deserialize, Serialize};
use serde_json;
use std::path::Path;
use std::str;
use std::process::Command;
use nix::unistd::{access, AccessFlags};
use reqwest::Client;
use std::fs::File;
use std::io::Write;
use tokio::runtime::Runtime;
use tokio::stream::StreamExt; 


/// Configuration information for DmVerity device.
#[derive(Debug, Deserialize, Serialize)]
pub struct DmVerityOption {
    /// Hash algorithm for dm-verity.
    pub hashtype: String,
    /// Root hash for device verification or activation.
    pub hash: String,
    /// Size of data device used in verification.
    pub blocknum: u64,
    /// Used block size for the data device.
    pub blocksize: u64,
    /// Used block size for the hash device.
    pub hashsize: u64,
    /// Offset of hash area/superblock on hash_device.
    pub offset: u64,
}

impl DmVerityOption {
    /// Validate configuration information for DmVerity device.
    pub fn validate(&self) -> Result<()> {
        match self.hashtype.to_lowercase().as_str() {
            "sha256" => {
                if self.hash.len() != 64 || hex::decode(&self.hash).is_err() {
                    bail!(
                        "Invalid hash value sha256:{} for DmVerity device with sha256",
                        self.hash,
                    );
                }
            }
            "sha1" => {
                if self.hash.len() != 40 || hex::decode(&self.hash).is_err() {
                    bail!(
                        "Invalid hash value sha1:{} for DmVerity device with sha1",
                        self.hash,
                    );
                }
            }
            // TODO: support ["sha224", "sha384", "sha512", "ripemd160"];
            _ => {
                bail!(
                    "Unsupported hash algorithm {} for DmVerity device {}",
                    self.hashtype,
                    self.hash,
                );
            }
        }

        if self.blocknum == 0 || self.blocknum > u32::MAX as u64 {
            bail!("Zero block count for DmVerity device {}", self.hash);
        }
        if !Self::is_valid_block_size(self.blocksize) || !Self::is_valid_block_size(self.hashsize) {
            bail!(
                "Unsupported verity block size: data_block_size = {},hash_block_size = {}",
                self.blocksize,
                self.hashsize
            );
        }
        if self.offset % self.hashsize != 0 || self.offset < self.blocksize * self.blocknum {
            bail!(
                "Invalid hashvalue offset {} for DmVerity device {}",
                self.offset,
                self.hash
            );
        }

        Ok(())
    }

    fn is_valid_block_size(block_size: u64) -> bool {
        for order in 9..20 {
            if block_size == 1 << order {
                return true;
            }
        }
        false
    }

    fn parse_tarfs_options(source_option: &str) -> std::result::Result<DmVerityOption, Error> {
        let mut parts: Vec<&str> = source_option.split(',').collect();
        if parts.len() == 3 {
            parts[2] = parts[2].trim_start_matches("sha256:");
        }
        Ok(DmVerityOption {
            hashtype: "sha256".to_string(),
            blocksize: 512, //default block size
            hashsize: 4096, //default hash size
            blocknum: parts[0].parse()?,
            offset: parts[1].parse()?,
            hash: parts[2].to_string(),
        })
    }
}

// Parse `DmVerityOption` object from plaintext or base64 encoded json string.
impl TryFrom<&str> for DmVerityOption {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let option = if value.contains("sha256:") {
            Self::parse_tarfs_options(value)?
        } else if let Ok(v) = serde_json::from_str::<DmVerityOption>(value) {
            v
        } else {
            let decoded = base64::engine::general_purpose::STANDARD.decode(value)?;
            serde_json::from_slice::<DmVerityOption>(&decoded)?
        };

        option.validate()?;
        Ok(option)
    }
}

impl TryFrom<&String> for DmVerityOption {
    type Error = Error;

    fn try_from(value: &String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

fn udev_running() -> bool {
    const UDEV_SOCKET_PATH: &str = "/run/udev/control";
    matches!(
        access(Path::new(UDEV_SOCKET_PATH), AccessFlags::F_OK),
        Ok(())
    )
}

fn start_udev() {
    let check_udev = Command::new("pgrep")
        .args(&["-x", "systemd-udevd"])
        .output()
        .expect("KS (image-rs) Failed to execute pgrep");

    if check_udev.status.success() {
        println!("KS (image-rs) udev daemon is already running.");
        println!("KS (image-rs) pgrep output: {}", str::from_utf8(&check_udev.stdout).unwrap());
    } else {
        println!("KS (image-rs) udev daemon is not running.");
        println!("KS (image-rs) pgrep stderr: {}", str::from_utf8(&check_udev.stderr).unwrap());
        println!("KS (image-rs) Attempting to start udev...");

        let cmds = [
            "/lib/systemd/systemd-udevd --daemon",
            "udevadm trigger",
            "udevadm settle",
        ];
        for cmd in cmds.iter() {
            let output = Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()
                .expect("KS (image-rs) Failed to execute udev command");

            if output.status.success() {
                println!("KS (image-rs) Command '{}' executed successfully.", cmd);
            } else {
                eprintln!("KS (image-rs) Failed to execute '{}': {}", cmd, str::from_utf8(&output.stderr).unwrap());
            }
        }
        let check_udev = Command::new("pgrep")
        .args(&["-x", "systemd-udevd"])
        .output()
        .expect("KS (image-rs) Failed to execute pgrep");

        if check_udev.status.success() {
            println!("KS (image-rs) udev daemon sucesfully started.");
            println!("KS (image-rs) pgrep output: {}", str::from_utf8(&check_udev.stdout).unwrap());
        } else {
            println!("KS (image-rs) udev daemon not started.");
            println!("KS (image-rs) pgrep stderr: {}", str::from_utf8(&check_udev.stderr).unwrap());
        }
    }
    if udev_running() {
        println!("KS udev/control is accessible.");
    } else {
        println!("KS udev/control is NOT accessible.");
    }
}

async fn dummy_prefetch() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let blob_ids = ["ac2c9c7c25e992c7a0f1b6261112df95281324d8229541317f763dfaf01c7f30", "c737fc16374b9e9a352300146ab49de56f0068e42618fe2ebe3323d4069b7b89"];
    let cache_dir = "/opt/nydus/cache/";

    fs::create_dir_all(cache_dir)?;

    for &blob_id in &blob_ids {
        let url = format!("https://external-registry.coco-csg.com/v2/tf-serving-tinybert/blobs/sha256:{}", blob_id);
        let response = client.get(&url).send().await?;

        if response.status().is_success() {
            let mut content = Vec::new();
            let mut content_stream = response.bytes_stream();
            while let Some(item) = content_stream.next().await {
                content.extend(item?);
            }

            let cache_path = format!("{}{}", cache_dir, blob_id);
            let mut file = File::create(cache_path)?;
            file.write_all(&content)?;
        } else {
            eprintln!("KS: Failed to fetch blob: {}", blob_id);
        }
    }

    let cmd = "ls /opt/nydus/cache/";
    let output = Command::new("sh")
    .arg("-c")
    .arg(cmd)
    .output()
    .expect("KS (image-rs) Failed to execute 'ls' command");

    if output.status.success() {
        let stdout = str::from_utf8(&output.stdout)
            .unwrap_or("KS Failed to decode stdout as UTF-8");

        for line in stdout.split('\n') {
            println!("KS blob: {}", line);
        }
    } else {
        let stderr = str::from_utf8(&output.stderr)
            .unwrap_or("KS Failed to decode stderr as UTF-8");
        eprintln!("KS Failed to execute '{}': {}", cmd, stderr);
    }

    Ok(())
}


/// Creates a mapping with <name> backed by data_device <source_device_path>
/// and using hash_device for in-kernel verification.
/// It will return the verity block device Path "/dev/mapper/<name>"
/// Notes: the data device and the hash device are the same one.
pub fn create_verity_device(
    verity_option: &DmVerityOption,
    source_device_path: &Path,
) -> Result<String> {
    println!("CSG-M4GIC: B3G1N: (KS-image-rs) create_verity_device, path: ({:?}), option: ({:?})", source_device_path, verity_option);

    let cmd = "ls /dev/mapper";
    let output = Command::new("sh")
    .arg("-c")
    .arg(cmd)
    .output()
    .expect("KS (image-rs) Failed to execute 'ls' command");

    if output.status.success() {
        let stdout = str::from_utf8(&output.stdout)
            .unwrap_or("KS Failed to decode stdout as UTF-8");

        for line in stdout.split('\n') {
            println!("KS mapper file: {}", line);
        }
    } else {
        let stderr = str::from_utf8(&output.stderr)
            .unwrap_or("KS Failed to decode stderr as UTF-8");
        eprintln!("KS Failed to execute '{}': {}", cmd, stderr);
    }

    let dm = DM::new()?;
    let verity_name = DmName::new(&verity_option.hash)?;
    let id = DevId::Name(verity_name);
    let opts = DmOptions::default().set_flags(DmFlags::DM_READONLY);
    let hash_start_block: u64 =
        (verity_option.offset + verity_option.hashsize - 1) / verity_option.hashsize;

    // verity parameters: <version> <data_device> <hash_device> <data_blk_size> <hash_blk_size>
    // <blocks> <hash_start> <algorithm> <root_hash> <salt>
    // version: on-disk hash version
    //     0 is the original format used in the Chromium OS.
    //     1 is the current format that should be used for new devices.
    // data_device: device containing the data the integrity of which needs to be checked.
    //     It may be specified as a path, like /dev/vdX, or a device number, major:minor.
    // hash_device: device that that supplies the hash tree data.
    //     It is specified similarly to the data device path and is the same device in the function of create_verity_device.
    //     The hash_start should be outside of the dm-verity configured device size.
    // data_blk_size: The block size in bytes on a data device.
    // hash_blk_size: The size of a hash block in bytes.
    // blocks: The number of data blocks on the data device.
    // hash_start: offset, in hash_blk_size blocks, from the start of hash_device to the root block of the hash tree.
    // algorithm: The cryptographic hash algorithm used for this device. This should be the name of the algorithm, like "sha256".
    // root_hash: The hexadecimal encoding of the cryptographic hash of the root hash block and the salt.
    // salt: The hexadecimal encoding of the salt value.
    let verity_params = format!(
        "1 {} {} {} {} {} {} {} {} {}",
        source_device_path.display(),
        source_device_path.display(),
        verity_option.blocksize,
        verity_option.hashsize,
        verity_option.blocknum,
        hash_start_block,
        verity_option.hashtype,
        verity_option.hash,
        "-",
    );
    println!("CSG-M4GIC: (KS-image-rs) dm_verity params: ({:?})", verity_params);

    start_udev();

    dummy_prefetch();

    // Mapping table in device mapper: <start_sector> <size> <target_name> <target_params>:
    // <start_sector> is 0
    // <size> is size of device in sectors, and one sector is equal to 512 bytes.
    // <target_name> is name of mapping target, here "verity" for dm-verity
    // <target_params> are parameters for verity target
    
    let verity_table = vec![(
       0,
       verity_option.blocknum * verity_option.blocksize / 512,
       "verity".into(),
       verity_params,
    )];

    //dm.device_create(verity_name, None, opts)?;
    let dev = dm.device_create(verity_name, None, opts).unwrap();

    println!("CSG-M4GIC: (KS-image-rs) Device created: {:?}", dev);

    // if let Err(ref e) = result {
    //     println!("CSG-M4GIC: (KS-image-rs) Error occurred while creating device: {}", e);
    //     result.unwrap();
    // }

    println!("KS (image-rs) verity device created");

    let dev_info = dm.table_load(&id, verity_table.as_slice(), opts)?;

    println!("CSG-M4GIC: KS (image-rs)  Loaded table with dev info: {:?}", dev_info);

    //println!("KS (image-rs) verity table loaded");

    //println!("KS (image-rs) dev info collected: {:?}", dev_info);

    let devs = dm.list_devices();

    println!("CSG-M4GIC: KS (image-rs) listing devices: {:?}", devs);

    //dm.device_suspend(&id, opts)?;

    let result = dm.device_suspend(&id, opts);
    println!("KS (image-rs) Device suspended result {:?}", result);
    match result {
        Ok(device_info) => {
            println!("KS (image-rs) Device suspended successfully. Device info: {:?}", device_info);
        },
        Err(e) => {
            println!("KS (image-rs) Error occurred while trying to suspend device: {:?}", e);
        }
    }
    println!("CSG-M4GIC: END: (KS-image-rs) create_verity_device");

    Ok(format!("/dev/mapper/{}", &verity_option.hash))
}

/// Destroy a DmVerity device with specified name.
pub fn destroy_verity_device(verity_device_name: &str) -> Result<()> {
    let dm = devicemapper::DM::new()?;
    let name = devicemapper::DmName::new(verity_device_name)?;

    dm.device_remove(
        &devicemapper::DevId::Name(name),
        devicemapper::DmOptions::default(),
    )
    .context(format!("remove DmverityDevice {}", verity_device_name))?;

    Ok(())
}

/// Get the DmVerity device name from option string.
pub fn get_verity_device_name(verity_options: &str) -> Result<String> {
    let option = DmVerityOption::try_from(verity_options)?;
    Ok(option.hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_decode_verity_options() {
        let verity_option = DmVerityOption {
            hashtype: "sha256".to_string(),
            blocksize: 512,
            hashsize: 512,
            blocknum: 16384,
            offset: 8388608,
            hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174".to_string(),
        };
        let json_option = serde_json::to_string(&verity_option).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json_option);

        let decoded = DmVerityOption::try_from(&encoded).unwrap_or_else(|err| panic!("{}", err));
        assert_eq!(decoded.hashtype, verity_option.hashtype);
        assert_eq!(decoded.blocksize, verity_option.blocksize);
        assert_eq!(decoded.hashsize, verity_option.hashsize);
        assert_eq!(decoded.blocknum, verity_option.blocknum);
        assert_eq!(decoded.offset, verity_option.offset);
        assert_eq!(decoded.hash, verity_option.hash);

        let decoded = DmVerityOption::try_from(&json_option).unwrap();
        assert_eq!(decoded.hashtype, verity_option.hashtype);
        assert_eq!(decoded.blocksize, verity_option.blocksize);
        assert_eq!(decoded.hashsize, verity_option.hashsize);
        assert_eq!(decoded.blocknum, verity_option.blocknum);
        assert_eq!(decoded.offset, verity_option.offset);
        assert_eq!(decoded.hash, verity_option.hash);

        let verity_option =
            "1024,524288,sha256:9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174";
        let decoded = DmVerityOption::try_from(verity_option).unwrap();
        assert_eq!(decoded.hashtype, "sha256");
        assert_eq!(decoded.blocksize, 512);
        assert_eq!(decoded.hashsize, 4096);
        assert_eq!(decoded.blocknum, 1024);
        assert_eq!(decoded.offset, 524288);
        assert_eq!(
            decoded.hash,
            "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
        );
    }

    #[tokio::test]
    async fn test_check_verity_options() {
        let tests = &[
            DmVerityOption {
                hashtype: "md5".to_string(), // "md5" is not a supported hash algorithm
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 3000, // Invalid block size, not a power of 2.
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 0, // Invalid block size, less than 512.
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 524800, // Invalid block size, greater than 524288.
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 3000, // Invalid hash block size, not a power of 2.
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 0, // Invalid hash block size, less than 512.
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 524800, // Invalid hash block size, greater than 524288.
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 0, // Invalid blocknum, it must be greater than 0.
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 0, // Invalid offset, it must be greater than 0.
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 8193, // Invalid offset, it must be aligned to 512.
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608 - 4096, // Invalid offset, it must be equal to blocksize * blocknum.
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
        ];
        for d in tests.iter() {
            d.validate().unwrap_err();
        }
        let test_data = DmVerityOption {
            hashtype: "sha256".to_string(),
            blocksize: 512,
            hashsize: 512,
            blocknum: 16384,
            offset: 8388608,
            hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174".to_string(),
        };
        test_data.validate().unwrap();
    }

    #[tokio::test]
    async fn test_create_verity_device() {
        let work_dir = tempfile::tempdir().unwrap();
        let file_name: std::path::PathBuf = work_dir.path().join("test.file");
        let data = vec![0u8; 1048576];
        fs::write(&file_name, data)
            .unwrap_or_else(|err| panic!("Failed to write to file: {}", err));

        let loop_control = loopdev::LoopControl::open().unwrap_or_else(|err| panic!("{}", err));
        let loop_device = loop_control
            .next_free()
            .unwrap_or_else(|err| panic!("{}", err));
        loop_device
            .with()
            .autoclear(true)
            .attach(file_name.to_str().unwrap())
            .unwrap_or_else(|err| panic!("{}", err));
        let loop_device_path = loop_device
            .path()
            .unwrap_or_else(|| panic!("failed to get loop device path"));

        let tests = &[
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 4096,
                blocknum: 1024,
                offset: 524288,
                hash: "fc65e84aa2eb12941aeaa29b000bcf1d9d4a91190bd9b10b5f51de54892952c6"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha1".to_string(),
                blocksize: 512,
                hashsize: 1024,
                blocknum: 1024,
                offset: 524288,
                hash: "e889164102360c7b0f56cbef6880c4ae75f552cf".to_string(),
            },
        ];
        for d in tests.iter() {
            let verity_device_path =
                create_verity_device(d, &loop_device_path).unwrap_or_else(|err| panic!("{}", err));
            assert_eq!(verity_device_path, format!("/dev/mapper/{}", d.hash));
            destroy_verity_device(&d.hash).unwrap();
        }
    }
}
