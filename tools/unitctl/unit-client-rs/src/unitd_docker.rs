use std::collections::HashMap;
use std::fs::read_to_string;
use std::path::PathBuf;

use crate::unitd_process::UnitdProcess;
use crate::unit_client::UnitClientError;
use bollard::{models::ContainerSummary, Docker};
use bollard::container::{Config, StartContainerOptions, ListContainersOptions};
use bollard::image::CreateImageOptions;
use bollard::secret::ContainerInspectResponse;
use bollard::models::{HostConfig, MountTypeEnum, Mount, ContainerCreateResponse};
use regex::Regex;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use crate::futures::StreamExt;


#[derive(Clone, Debug)]
pub struct UnitdContainer {
    pub container_id: Option<String>,
    pub container_image: String,
    pub command: Option<String>,
    pub mounts: HashMap<PathBuf, PathBuf>,
    pub platform: String,
    details: Option<ContainerInspectResponse>,
}

impl From<&ContainerSummary> for UnitdContainer {
    fn from(ctr: &ContainerSummary) -> Self {
        // we assume paths from the docker api are absolute
        // they certainly have to be later...
        let mut mounts = HashMap::new();
        if let Some(mts) = &ctr.mounts {
            for i in mts {
                if let Some(ref src) = i.source {
                    if let Some(ref dest) = i.destination {
                        mounts.insert(PathBuf::from(dest.clone()), PathBuf::from(src.clone()));
                    }
                }
            }
        }

        UnitdContainer {
            container_id: ctr.id.clone(),
            container_image: format!(
                "{} (docker)",
                ctr.image.clone().unwrap_or(String::from("unknown container")),
            ),
            command: ctr.command.clone(),
            mounts: mounts,
            platform: String::from("Docker"),
            details: None,
        }
    }
}

impl From<&UnitdContainer> for UnitdProcess {
    fn from(ctr: &UnitdContainer) -> Self {
        let version = ctr.details.as_ref().and_then(|details| {
            details.config.as_ref().and_then(|conf| {
                conf.labels.as_ref().and_then(|labels| {
                    labels
                        .get("org.opencontainers.image.version")
                        .and_then(|version| Some(version.clone()))
                })
            })
        });
        let command = ctr.command.clone().and_then(|cmd| {
            Some(format!(
                "{}{} [{}{}]",
                "unit: main v",
                version.or(Some(String::from(""))).unwrap(),
                ctr.container_image,
                ctr.rewrite_socket(
                    cmd.strip_prefix("/usr/local/bin/docker-entrypoint.sh")
                        .or_else(|| Some(""))
                        .unwrap()
                        .to_string())
            ))
        });
        let mut cmds = vec![];
        let _ = command.map_or((), |cmd| cmds.push(cmd));
        UnitdProcess {
            all_cmds: cmds,
            binary_name: ctr.container_image.clone(),
            process_id: ctr
                .details
                .as_ref()
                .and_then(|details| {
                    details
                        .state
                        .as_ref()
                        .and_then(|state| state.pid.and_then(|pid| Some(pid.clone() as u64)))
                })
                .or(Some(0 as u64))
                .unwrap(),
            executable_path: None,
            environ: vec![],
            working_dir: ctr.details.as_ref().and_then(|details| {
                details.config.as_ref().and_then(|conf| {
                    Some(
                        PathBuf::from(
                            conf.working_dir
                                .as_ref()
                                .map_or(String::new(), |dir| ctr.host_path(dir.clone())),
                        )
                        .into_boxed_path(),
                    )
                })
            }),
            child_pids: vec![],
            user: None,
            effective_user: None,
            container: Some(ctr.clone()),
        }
    }
}

impl Serialize for UnitdContainer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_map(Some(5))?;
        state.serialize_entry("container_id", &self.container_id)?;
        state.serialize_entry("container_image", &self.container_image)?;
        state.serialize_entry("command", &self.command)?;
        state.serialize_entry("mounts", &self.mounts)?;
        state.serialize_entry("platform", &self.platform)?;
        state.end()
    }
}

impl UnitdContainer {
    pub async fn find_unitd_containers() -> Vec<UnitdContainer> {
        if let Ok(docker) = Docker::connect_with_local_defaults() {
            match docker.list_containers::<String>(None).await {
                Err(e) => {
                    eprintln!("{}", e);
                    vec![]
                }
                Ok(summary) => {
                    // cant do this functionally because of the async call
                    let mut mapped = vec![];
                    for ctr in summary {
                        if ctr.clone().image.or(Some(String::new())).unwrap().contains("unit") {
                            let mut c = UnitdContainer::from(&ctr);
                            if let Some(names) = ctr.names {
                                if names.len() > 0 {
                                    let name = names[0].strip_prefix("/").or(Some(names[0].as_str())).unwrap();
                                    if let Ok(cir) = docker.inspect_container(name, None).await {
                                        c.details = Some(cir);
                                    }
                                }
                            }
                            mapped.push(c);
                        }
                    }
                    mapped
                }
            }
        } else {
            vec![]
        }
    }

    pub fn host_path(&self, container_path: String) -> String {
        let cp = PathBuf::from(container_path);

        // get only possible mount points
        // sort to deepest mountpoint first
        // assumed deepest possible mount point takes precedence
        let mut keys = self
            .mounts
            .clone()
            .into_keys()
            .filter(|mp| cp.as_path().starts_with(mp))
            .collect::<Vec<_>>();
        keys.sort_by_key(|a| 0 as isize - a.ancestors().count() as isize);

        // either return translated path or original prefixed with "container"
        if keys.len() > 0 {
            self.mounts[&keys[0]]
                .clone()
                .join(
                    cp.as_path()
                        .strip_prefix(keys[0].clone())
                        .expect("error checking path prefix"),
                )
                .to_string_lossy()
                .to_string()
        } else {
            format!("<container>:{}", cp.display())
        }
    }

    pub fn rewrite_socket(&self, command: String) -> String {
        command
            .split(" ")
            .map(|tok| if tok.starts_with("unix:") {
                format!("unix:{}", self.host_path(
                    tok.strip_prefix("unix:")
                        .unwrap()
                        .to_string()))
            } else {
                tok.to_string()
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn container_is_running(&self) -> Option<bool> {
        self.details
            .as_ref()
            .and_then(|details| details.state.as_ref().and_then(|state| state.running))
    }
}

/* deploys a new docker image of tag $image_tag.
 * mounts $socket to /var/run in the new container.
 * mounts $application read only to /www.
 * new container is on host network.
 *
 * ON SUCCESS returns vector of warnings from Docker API
 * ON FAILURE returns wrapped error from Docker API
 */
pub async fn deploy_new_container(
    socket: &String,
    application: &String,
    image: &String
) -> Result<Vec<String>, UnitClientError> {
    match Docker::connect_with_local_defaults() {
        Ok(docker) => {
            let mut mounts = vec![];
            mounts.push(Mount{
                typ: Some(MountTypeEnum::BIND),
                source: Some(socket.clone()),
                target: Some("/var/run".to_string()),
                ..Default::default()
            });
            mounts.push(Mount{
                typ: Some(MountTypeEnum::BIND),
                source: Some(application.clone()),
                target: Some("/www".to_string()),
                read_only: Some(true),
                ..Default::default()
            });

            let _ = docker.create_image(
                Some(CreateImageOptions {
                    from_image: image.as_str(),
                    ..Default::default()
                }), None, None)
                .next()
                .await
                .unwrap()
                .or_else(|err| Err(UnitClientError::UnitdDockerError{message: err.to_string()}));

            let resp: ContainerCreateResponse;
            match docker.create_container::<String, String>(
                None, Config {
                    image: Some(image.clone()),
                    host_config: Some(HostConfig {
                        network_mode: Some("host".to_string()),
                        mounts: Some(mounts),
                        ..Default::default()
                    }), ..Default::default()})
                .await {
                    Err(err) => return Err(UnitClientError::UnitdDockerError{message: err.to_string()}),
                    Ok(response) => resp = response,
                }

            let mut list_container_filters = HashMap::new();
            list_container_filters.insert("id".to_string(), vec![resp.id]);
            match docker.list_containers::<String>(
                Some(ListContainersOptions{
                    all: true,
                    limit: None,
                    size: false,
                    filters: list_container_filters,
                }))
                .await {
                    Err(e) => Err(UnitClientError::UnitdDockerError{message: e.to_string()}),
                    Ok(info) => {
                        if info.len() < 1 {
                            return Err(UnitClientError::UnitdDockerError{message: "couldnt find new container".to_string()});
                        }
                        if info[0].names.is_none() || info[0].names.clone().unwrap().len() < 1 {
                            return Err(UnitClientError::UnitdDockerError{message: "new container has no name".to_string()});
                        }

                        match docker.start_container(
                            info[0]
                                .names
                                .clone()
                                .unwrap()[0]
                                .strip_prefix("/")
                                .unwrap(),
                            None::<StartContainerOptions<String>>
                        ).await {
                            Err(err) => Err(UnitClientError::UnitdDockerError{message: err.to_string()}),
                            Ok(_) => Ok(resp.warnings)
                        }
                    }
                }
        },
        Err(e) => Err(UnitClientError::UnitdDockerError{message: e.to_string()})
    }
}

/* Returns either 64 char docker container ID or None */
pub fn pid_is_dockerized(pid: u64) -> bool {
    let cg_filepath = format!("/proc/{}/cgroup", pid);
    match read_to_string(cg_filepath) {
        Err(e) => {
            eprintln!("{}", e);
            false
        }
        Ok(contents) => {
            let docker_re = Regex::new(r"docker-([a-zA-Z0-9]{64})").unwrap();
            docker_re.is_match(contents.as_str())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_translation() {
        let mut mounts = HashMap::new();
        mounts.insert("/1/2/3/4/5/6/7".into(), "/0".into());
        mounts.insert("/root".into(), "/1".into());
        mounts.insert("/root/mid".into(), "/2".into());
        mounts.insert("/root/mid/child".into(), "/3".into());
        mounts.insert("/mid/child".into(), "/4".into());
        mounts.insert("/child".into(), "/5".into());

        let ctr = UnitdContainer {
            container_id: None,
            container_image: String::from(""),
            command: None,
            platform: "test".to_string(),
            details: None,
            mounts: mounts,
        };

        assert_eq!(
            "/3/c2/test".to_string(),
            ctr.host_path("/root/mid/child/c2/test".to_string())
        );
        assert_eq!(
            "<container>:/path/to/conf".to_string(),
            ctr.host_path("/path/to/conf".to_string())
        );
    }

    #[test]
    fn test_unix_sock_path_translate() {
        let mut mounts = HashMap::new();
        mounts.insert("/var/run".into(), "/tmp".into());

        let ctr = UnitdContainer {
            container_id: None,
            container_image: String::from(""),
            command: None,
            platform: "test".to_string(),
            details: None,
            mounts: mounts,
        };

        assert_eq!(
            ctr.rewrite_socket("unitd --no-daemon --control unix:/var/run/control.unit.sock".to_string()),
            "unitd --no-daemon --control unix:/tmp/control.unit.sock".to_string());

    }
}
