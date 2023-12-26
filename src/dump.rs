use std::sync::{OnceLock, Mutex};
use std::net::{Ipv4Addr, Ipv6Addr};
use log::warn;
use rpki::repository::resources::{
    AsBlocks, IpBlocks,
};
use rpki::repository::roa::{RoaIpAddresses, RouteOriginAttestation};
use rpki::repository::cert::ResourceCert;
use rpki::crypto::keys::{KeyIdentifier, PublicKey};

use rpki::repository::x509::{Time, Name};
use serde::{ser::{SerializeSeq, SerializeStruct}, Serialize};

pub struct CaCertDump {
    parent: KeyIdentifier,
    id: KeyIdentifier,
    issuer: Name,
    subject: Name,
    pubkey: PublicKey,
    v4_resources: IpBlocks,
    v6_resources: IpBlocks,
    as_resources: AsBlocks,
    not_before: Time,
    not_after: Time,
}

struct Unpackedv4(IpBlocks);

#[derive(Serialize)]
struct V4Block {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

impl Serialize for Unpackedv4 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        let mut state = serializer.serialize_seq(None)?;
        for v4 in self.0.iter() {
            let start = v4.min().to_v4();
            let end = v4.max().to_v4();
            let block = V4Block {
                start,
                end,
            };
            state.serialize_element(&block)?;
        }
        state.end()
    }
}

struct Unpackedv6(IpBlocks);

#[derive(Serialize)]
struct V6Block {
    start: Ipv6Addr,
    end: Ipv6Addr,
}

impl Serialize for Unpackedv6 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        let mut state = serializer.serialize_seq(None)?;
        for v6 in self.0.iter() {
            let start = v6.min().to_v6();
            let end = v6.max().to_v6();
            let block = V6Block {
                start,
                end,
            };
            state.serialize_element(&block)?;
        }
        state.end()
    }
}

impl Serialize for CaCertDump {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        let mut state = serializer.serialize_struct("CaCertDump", 9)?;
        state.serialize_field("parent", &self.parent)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("issuer", &self.issuer)?;
        state.serialize_field("subject", &self.subject)?;
        state.serialize_field("pubkey", &self.pubkey)?;
        let v4 = Unpackedv4(self.v4_resources.clone());
        state.serialize_field("v4_resources", &v4)?;
        let v6 = Unpackedv6(self.v6_resources.clone());
        state.serialize_field("v6_resources", &v6)?;
        state.serialize_field("as_resources", &self.as_resources)?;
        state.serialize_field("not_before", &self.not_before)?;
        state.serialize_field("not_after", &self.not_after)?;
        state.end()
    }
}

pub struct ROADump {
    parent: KeyIdentifier,
    id: KeyIdentifier,
    issuer: Name,
    subject: Name,
    pubkey: PublicKey,
    v4_resources: RoaIpAddresses,
    v6_resources: RoaIpAddresses,
    as_number: u32,
    not_before: Time,
    not_after: Time,
}

struct UnpackedRoav4(RoaIpAddresses);

#[derive(Serialize)]
struct V4Roa {
    start: Ipv4Addr,
    end: Ipv4Addr,
    max_length: u8,
}

impl Serialize for UnpackedRoav4 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        let mut state = serializer.serialize_seq(None)?;
        for v4 in self.0.iter() {
            let (start, end) = v4.range();
            let ml = v4.max_length().unwrap_or(0);
            let roa = V4Roa {
                start: start.to_v4(),
                end: end.to_v4(),
                max_length: ml,
            };
            state.serialize_element(&roa)?;
        }
        state.end()
    }
}

struct UnpackedRoav6(RoaIpAddresses);

#[derive(Serialize)]
struct V6Roa {
    start: Ipv6Addr,
    end: Ipv6Addr,
    max_length: u8,
}

impl Serialize for UnpackedRoav6 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        let mut state = serializer.serialize_seq(None)?;
        for v6 in self.0.iter() {
            let (start, end) = v6.range();
            let ml = v6.max_length().unwrap_or(0);
            let roa = V6Roa {
                start: start.to_v6(),
                end: end.to_v6(),
                max_length: ml,
            };
            state.serialize_element(&roa)?;
        }
        state.end()
    }
}

impl Serialize for ROADump {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        let mut state = serializer.serialize_struct("ROADump", 9)?;
        state.serialize_field("parent", &self.parent)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("issuer", &self.issuer)?;
        state.serialize_field("subject", &self.subject)?;
        state.serialize_field("pubkey", &self.pubkey)?;
        state.serialize_field("as_number", &self.as_number)?;
        let uv4 = UnpackedRoav4(self.v4_resources.clone());
        state.serialize_field("v4_resources", &uv4)?;
        let uv6 = UnpackedRoav6(self.v6_resources.clone());
        state.serialize_field("v6_resources", &uv6)?;
        state.serialize_field("not_before", &self.not_before)?;
        state.serialize_field("not_after", &self.not_after)?;
        state.end()
    }
}

struct TALDump {
    id: KeyIdentifier,
    name: String,
}

impl Serialize for TALDump {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        let mut state = serializer.serialize_struct("TALDump", 2)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("name", &self.name)?;
        state.end()
    }
}

#[derive(Serialize)]
pub struct DBDump {
    tals: Vec<TALDump>,
    ca_certs: Vec<CaCertDump>,
    roas: Vec<ROADump>,
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
        rcert: &ResourceCert
    ) {
        let pk = rcert.subject_key_identifier();
        let parent_pk = rcert.authority_key_identifier();
        if let Some(pk) = parent_pk {
            if parent != pk {
                warn!("Parent field mismatch in {}", pk);
                warn!("  Expected: {}", parent);
                warn!("  Got: {}", pk);
            }
        } else {
            warn!("No parent field in {}", pk)
        }
        let issuer = rcert.issuer();
        let subject = rcert.subject();
        let pk_full = rcert.subject_public_key_info();
        let v4 = rcert.v4_resources();
        let v6 = rcert.v6_resources();
        let asn = rcert.as_resources();
        let validity = rcert.validity();
        let (l, r) = (validity.not_before(), validity.not_after());
        self.ca_certs.push(CaCertDump {
            parent,
            id: pk,
            issuer: issuer.clone(),
            subject: subject.clone(),
            pubkey: pk_full.clone(),
            v4_resources: v4.clone(),
            v6_resources: v6.clone(),
            as_resources: asn.clone(),
            not_before: l,
            not_after: r,
        });
    }

    pub fn add_roa(
        &mut self,
        parent: KeyIdentifier,
        rcert: &ResourceCert,
        route: &RouteOriginAttestation,
    ) {
        let pk = rcert.subject_key_identifier();
        let pk_full = rcert.subject_public_key_info();
        let parent_pk = rcert.authority_key_identifier();
        if let Some(pk) = parent_pk {
            if parent != pk {
                warn!("Parent field mismatch in {}", pk);
                warn!("  Expected: {}", parent);
                warn!("  Got: {}", pk);
            }
        } else {
            warn!("No parent field in {}", pk)
        }
        let issuer = rcert.issuer();
        let subject = rcert.subject();
        let v4 = route.v4_addrs();
        let v6 = route.v6_addrs();
        let asn = route.as_id();
        let validity = rcert.validity();
        let (l, r) = (validity.not_before(), validity.not_after());
        self.roas.push(ROADump {
            parent,
            id: pk,
            issuer: issuer.clone(),
            subject: subject.clone(),
            pubkey: pk_full.clone(),
            v4_resources: v4.clone(),
            v6_resources: v6.clone(),
            as_number: asn.into(),
            not_before: l,
            not_after: r,
        });
    }

    pub fn add_tal(&mut self, id: KeyIdentifier, name: &str) {
        self.tals.push(TALDump {
            id,
            name: name.to_string(),
        });
    }

    pub fn dump(&self) {
        let json = serde_json::to_string_pretty(&self).unwrap();
        println!("{}", json);
        /*
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
        */
    }
}

pub static DB_DUMP: OnceLock<Mutex<DBDump>> = OnceLock::new();
