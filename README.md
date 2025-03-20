# bitbucket-build-status-resource

[![Docker Pulls](https://img.shields.io/docker/pulls/shyxormz/bitbucket-build-status-resource.svg?maxAge=2592000)](https://hub.docker.com/r/shyxormz/bitbucket-build-status-resource/)
[![Build Status](https://travis-ci.org/SHyx0rmZ/bitbucket-build-status-resource.svg?branch=master)](https://travis-ci.org/SHyx0rmZ/bitbucket-build-status-resource)

This is a fork of https://github.com/Karunamon/concourse-resource-bitbucket.
The following forks have been merged in, too:
* https://github.com/Fydon/concourse-resource-bitbucket
* https://github.com/mehtaphysical/concourse-resource-bitbucket
* https://github.com/aecepoglu/concourse-resource-bitbucket
* https://github.com/ecometrica/concourse-resource-bitbucket
* https://github.com/Meshcloud/concourse-resource-bitbucket

You can find a pre-built [Docker image on DockerHub](https://hub.docker.com/r/shyxormz/bitbucket-build-status-resource/).
If you come from one of the integrated forks, you can use the image with tag `compatibility`, which should work without you changing anything else.

## Source Configuration

These items go in the `source` fields of the resource type. Bold items are required:
 * `debug` - *Optional.* *Default: `false`.* When `true`, dump the JSON documents sent and received for troubleshooting.
 * `driver` - *Optional.* *Default: `Bitbucket Server`.* The driver to use to set the build status.
 
There are two supported drivers, with their own sets of properties for configuring them.

### `Bitbucket Cloud` Driver
 * `repository` - *Required*. Full (`<ownername>/<repositoryname>`) repository name on Bitbucket Cloud to set build status for. 
 * `repo` - *Required.* **DEPRECATED. Use `repository` instead.** Full repository name on bitbucket to set build status in. (`<ownername>/<repositoryname>`).
 * `owner` - *Required.* **DEPRECATED. Use `repository` instead.** The owner of the repository, which will either be a username or team.
 * `repository_name` - *Required.* **DEPRECATED. Use `repository` instead.** The name of the repository on Bitbucket Cloud.

#### Authentication

One of the following two sets of properties must be specified:

##### Username and password

 * `username` - *Required*. Login name.
 * `password` - *Required*. An [app password](https://confluence.atlassian.com/bitbucket/app-passwords-828781300.html) with permission to read from and write to a repository.

##### OAuth client id and secert
 * `client_id` - *Required*. Client id of the OAuth consumer. Shown as `Key` in the bitbucket interface.
 * `client_secret` - *Required*. Client secret of the OAuth consumer.
 * `secret` - *Required.* **DEPRECATED. Use `client_secret` instead.** Client secret of the OAuth consumer.

###### Creating an Access Token
You need to create an OAuth access token for your Bitbucket Cloud team/user account with the following permissions: `Webhooks (r/w), Repositories (r)`

Make sure to **provide a callback URL** (it's not needed at runtime but OAuth insists on it anyway). For example, you can use the URL of your Concourse instance. Otherwise you will see an error similar to the following:
```
Access token result: <Response [400]>{"error_description": "No callback uri defined for the OAuth client.", "error": "invalid_request"}
HTTP 401 Unauthorized - Are your bitbucket credentials correct?
```

### `Bitbucket Server` Driver
* `endpoint` - *Required*. URL to a Bitbucket Server instance.
* `username` - *Required (if token is not set)*. Login name of someone with rights to the repository which's build status should be updated.
* `password` - *Required (if token is not set)*. Password associated with that login.
* `token` - *Optional*. Token to use with bearer-token auth. If set username and password are not required anymore.
* `verify_ssl` - *Optional.* *Default: `true`.* When `false`, ignore any HTTPS connection errors if generated. Useful if on an internal network.
* `bitbucket_url` - *Required*. **DEPRECATED. Use `endpoint` instead.** URL of the bitbucket instance, including a trailing slash.
* `bitbucket_username` - *Required*. **DEPRECATED. Use `username` instead.** Login username of someone with rights to the repository being updated.
* `bitbucket_password` - *Required*. **DEPRECATED. Use `password` instead.** Password for the mentioned user. 
## Behavior

### `check`: Not supported

### `in`: Not supported

### `out`: Update the build status of a commit

#### Parameters
* `repository` - *Required.* Name of the repository containing the commit whose build status should be updated.
This will come from a previous `get` on a `git/hg` resource.
Make sure to use the directory name, not the name of the resource.

* `build_status` - *Required.* The build status. Must be one of `SUCCESSFUL`, `FAILED`, or `INPROGRESS`.

* `key` - *Optional.* *Default: `ENV['BUILD_JOB_NAME']`.* Use the given key in build notification.
If different notifications have the same key, they will replace each other.

* `name` - *Optional.* *Default: `ENV['BUILD_NAME']`.* Use the given name in build notification.
This will show up on Bitbucket. For example "unit tests", "end to end tests"

* `build_url_file` - *Optional.* Link to the URL given in the file. If not specified, the build status will link to `<concourse-url>/teams/<team>/pipelines/<pipeline>/jobs/<job>/builds/<build>`.

* `description_file` - *Optional.* A path to a file containing a description of the
build. For example: "7 tests have failed". If not specified, the description will default to `"Concourse CI build, hijack as #<build-id>"`.

* `commit_hash_file` - *Optional*: A path to a file containing a commit hash. When specified, `repository` is no longer required and this option takes precedence.  This is useful in case you don't have the repository checked out or you have logic inside a task that computes the correct commit to update.

* `repo` - *Required.* **DEPRECATED. Use `repository` instead.** Name of the
repository containing the commit hash to be updated.
This will come from a previous `get` on a `git/hg` resource.
Make sure to use the directory name, not the name of the resource.

* `state` - *Required.* **DEPRECATED. Use `build_status` instead.** The build
status. Must be one of `SUCCESSFUL`, `FAILED`, or `INPROGRESS`.

## Example

A typical use case is to update the build status of a commit as it traverses your pipeline.
The following example marks the commit as pending before unit tests start.
Once unit tests finish, the build status is updated to either success or failure depending on how the task completes.

---
    resource_types:
      - name: bitbucket-build-status
        type: docker-image
        source:
          repository: shyxormz/bitbucket-build-status-resource

    resources:
      - name: testing-repo
        type: git
        source:
          uri: https://bitbucket.org/someuser/somerepo.git
          branch: master

      - name: build-status
        type: bitbucket-build-status
        source:
          client_id: cid
          client_secret: hemligt
          repository: someuser/somerepo

    jobs:
      - name: unit-tests
        plan:
        - get: testing-repo
          trigger: true

        - put: build-status
          params:
            build_status: INPROGRESS
            repository: testing-repo

        - task: tests
          file: testing-repo/task.yml
          on_success:
            put: build-status
            params:
              build_status: SUCCESSFUL
              repository: testing-repo
          on_failure:
            put: build-status
            params:
              build_status: FAILED
              repository: testing-repo

In this example, notice that the `repository` parameter is set to the same name as the `testing-repo` resource.
To reiterate: **In your deployment, set the `repository` field to the directory name of the repository**, or in other words,
what you'd end up with if you ran a `git/hg clone` against the URI.

To install on all Concourse workers, update your deployment manifest properties to include a new `groundcrew.resource_types` entry...

    properties:
      groundcrew:
        additional_resource_types:
          - image: "docker:///shyxormz/bitbucket-build-status-resource#latest"
            type: "bitbucket-build-status"

### Pipeline-specific

To use on a single pipeline, update your pipeline to include a new `resource_types` entry...

    resource_types:
      - name: bitbucket-build-status
        type: docker-image
        source:
          repository: shyxormz/bitbucket-build-status-resource
          tag: latest

## Low hanging improvement fruit
This is a work in progress and there are multiple areas that could use some improvement.
Any contribution is welcomed.

* Need to specify the repo explicitly in the source parameters.
  Change this to read the correct remote url from the repo itself.
* Fix tests.
* Write more tests.

## References

 * [Resources (Concourse CI)](https://concourse-ci.org/resources.html)
 * [Implementing a Resource Type (Concourse CI)](https://concourse-ci.org/implementing-resource-types.html)
 * [Bitbucket build status API](https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Bworkspace%7D/%7Brepo_slug%7D/commit/%7Bcommit%7D/statuses/build)

## Thanks
* [Karunamon](https://github.com/Karunamon) for getting the ball rolling.

## License

[Apache License v2.0]('./LICENSE')

