use std::sync::{OnceLock, Mutex};

use rpki::repository::resources::{
    AsBlocks, IpBlocks,
};
use rpki::repository::roa::RoaIpAddresses;
use rpki::crypto::keys::KeyIdentifier;

pub struct CaCertDump {
    parent: KeyIdentifier,
    id: KeyIdentifier,
    v4_resources: IpBlocks,
    v6_resources: IpBlocks,
    as_resources: AsBlocks,
}

pub struct ROADump {
    parent: KeyIdentifier,
    id: KeyIdentifier,
    v4_resources: RoaIpAddresses,
    v6_resources: RoaIpAddresses,
    as_number: u32,
}

pub struct DBDump {
    ca_certs: Vec<CaCertDump>,
    roas: Vec<ROADump>,
    tals: Vec<KeyIdentifier>,
}

impl DBDump {
    pub fn new() -> Self {
        DBDump {
            ca_certs: Vec::new(),
            roas: Vec::new(),
            tals: Vec::new(),
        }
    }

    pub fn add_ca_cert(
        &mut self,
        parent: KeyIdentifier,
        id: KeyIdentifier,
        v4_resources: IpBlocks,
        v6_resources: IpBlocks,
        as_resources: AsBlocks,
    ) {
        self.ca_certs.push(CaCertDump {
            parent,
            id,
            v4_resources,
            v6_resources,
            as_resources,
        });
    }

    pub fn add_roa(
        &mut self,
        parent: KeyIdentifier,
        id: KeyIdentifier,
        v4_resources: RoaIpAddresses,
        v6_resources: RoaIpAddresses,
        as_number: u32,
    ) {
        self.roas.push(ROADump {
            parent,
            id,
            v4_resources,
            v6_resources,
            as_number,
        });
    }

    pub fn add_tal(&mut self, id: KeyIdentifier) {
        self.tals.push(id);
    }

    pub fn dump(&self) {
        println!("TALs:");
        for tal in &self.tals {
            println!("  ID: {}", tal);
        }
        println!("CA Certs:");
        for ca_cert in &self.ca_certs {
            println!("  Parent: {}", ca_cert.parent);
            println!("  ID: {}", ca_cert.id);
            println!("  AS Resources: {}", ca_cert.as_resources);
            println!("  IPv4 Resources: {}", ca_cert.v4_resources.as_v4());
            println!("  IPv6 Resources: {}", ca_cert.v6_resources.as_v6());
        }
        println!("ROAs:");
        for roa in &self.roas {
            println!("  Parent: {}", roa.parent);
            println!("  ID: {}", roa.id);
            println!("  AS Number: {}", roa.as_number);
            for v4 in roa.v4_resources.iter() {
                let prefix = v4.prefix().to_v4();
                let ml = v4.max_length().unwrap_or(0);
                println!("    IPv4: {} Max: {}", prefix, ml);
            }
            for v6 in roa.v6_resources.iter() {
                let prefix = v6.prefix().to_v6();
                let ml = v6.max_length().unwrap_or(0);
                println!("    IPv6: {} Max: {}", prefix, ml);
            }
        }
    }
}

pub static DB_DUMP: OnceLock<Mutex<DBDump>> = OnceLock::new();
