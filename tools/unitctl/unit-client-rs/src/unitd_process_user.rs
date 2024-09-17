use serde::Serialize;
use std::fmt;
use std::fmt::Display;
use sysinfo::User;

#[derive(Debug, Clone, Serialize)]
pub struct UnitdProcessUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<String>,
}

impl Display for UnitdProcessUser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "name: {}, uid: {}, gid: {}, groups: {}",
            self.name,
            self.uid,
            self.gid,
            self.groups.join(", ")
        )
    }
}

impl From<&User> for UnitdProcessUser {
    fn from(user: &User) -> Self {
        UnitdProcessUser {
            name: user.name().into(),
            uid: *user.id().clone(),
            gid: *user.group_id(),
            groups: user.groups().iter().map(|g| g.name().into()).collect(),
        }
    }
}
