use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct ClientInfo {
    pub peer_ip: IpAddr,
    pub client_ip: IpAddr,
    pub source: IpSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpSource {
    Direct,
    Forwarded,
}

impl IpSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "peer",
            Self::Forwarded => "xff",
        }
    }
}

#[derive(Clone, Debug)]
pub enum AuditContext {
    Request(ClientInfo),
    Agent { agent_id: String },
    System,
}
