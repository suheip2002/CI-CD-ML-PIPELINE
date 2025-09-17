## GitHub Advisory Database 

A database of CVEs and GitHub-originated security advisories affecting the open source world. 

The database is free and open source and is a tool for and by the community.

Submit pull requests to help improve our database of software vulnerability information for all.

## Goals

* To provide a free and open-source repository of security advisories. 
* To enable our community to crowd-source their knowledge about these advisories. 
* To surface vulnerabilities in an industry-accepted formatting standard for machine interoperability. 

## Features 

All advisories acknowledged by GitHub are stored as individual files in this repository. They are formatted in the [Open Source Vulnerability (OSV) format](https://ossf.github.io/osv-schema/). 

You can submit a pull request to this database (see, [`Contributions`](#contributions)) to change or update the information in each advisory. 

Pull requests will be reviewed and either merged or closed by our internal security advisory curation team. If the advisory originated from a GitHub repository, we will also @mention the original publisher for optional commentary. 

## Sources 

We add advisories to the GitHub Advisory Database from the following sources:

- [Security advisories reported on GitHub](https://docs.github.com/en/code-security/security-advisories/repository-security-advisories/about-repository-security-advisories)
- The [National Vulnerability Database](https://nvd.nist.gov/)
- The [npm Security Advisories Database](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm)
- The [FriendsOfPHP Database](https://github.com/FriendsOfPHP/security-advisories)
- The [Go Vulnerability Database](https://vuln.go.dev/)
- The [Python Packaging Advisory Database](https://github.com/pypa/advisory-database)
- The [Ruby Advisory Database](https://rubysec.com/)
- The [RustSec Advisory Database](https://rustsec.org/)
- [Community contributions to this repository](https://github.com/github/advisory-database/pulls)

If you know of another database we should be importing advisories from, tell us about it by [opening an issue in this repository](https://github.com/github/advisory-database/issues). 

## Contributions

There are two ways to contribute to the information provided in this repository. 

From any individual advisory on [github.com/advisories](https://github.com/advisories), click **Suggest improvements for this vulnerability** (shown below) to open an "Improve security advisory" form. Edit the information in the form and click **Submit improvements** to open a pull request with your proposed changes. 

![Screen shot showing the "Suggest improvements for this vulnerability" link in the right sidebar](https://user-images.githubusercontent.com/8700883/153685286-34c8416e-7021-4a85-b140-a0e5758c959b.png)

Alternatively, you can submit a pull request directly against a file in this repository. To do so, follow the [contribution guidelines](https://github.com/github/advisory-database/blob/main/CONTRIBUTING.md). 

### References

Advisory references are intended to be supplemental, relevant information for the reader. We aim to include primary source references provided by the CVE or GHSA authors, supplement with relevant code or documentation when applicable, and focus on concision and relevance for any additional references. We generally avoid including secondary source write ups on advisories unless they are provided by the upstream source.
    
### Fix commits

Advisories are about specific build artifacts, and not about the project more generally. A reference to the commit that fixes a given vulnerability is helpful for downstream readers to determine impact, and we welcome contributions adding these details when missing. If the advisory already includes the relevant fix commit(s), we do not accept contributions that are duplicative, as adding irrelevant duplicate content creates an unnecessary burden on the reader of an advisory.


## Supported ecosystems 

Unfortunately, we cannot accept community contributions to advisories outside of our supported ecosystems. Our curation team reviews each community contribution thoroughly and needs to be able to assess each change. 

Generally speaking, our ecosystems are the namespace used by a package registry. As such they’re focused on packages within the registry which tend to be dependencies used in software development.

Our supported ecosystems are:

- Composer (registry: https://packagist.org)
- Erlang (registry: https://hex.pm/)
- GitHub Actions (registry: https://github.com/marketplace?type=actions)
- Go (registry: https://pkg.go.dev/)
- Maven (registry: https://repo.maven.apache.org/maven2)
- npm (registry: https://www.npmjs.com/)
- NuGet (registry: https://www.nuget.org/)
- pip (registry: https://pypi.org/)
- Pub (registry: https://pub.dev/)
- RubyGems (registry: https://rubygems.org/)
- Rust (registry: https://crates.io/)
- Swift (registry: [namespaced by dns](https://datatracker.ietf.org/doc/html/rfc1035))

If you have a suggestion for a new ecosystem we should support, please open an [issue](https://github.com/github/advisory-database/issues) for discussion.

## License 

This project is licensed under the terms of the CC-BY 4.0 open source license. Please [see our documentation](https://docs.github.com/en/github/site-policy/github-terms-for-additional-products-and-features#12-advisory-database) for the full terms.

## GHSA IDs

Each security advisory, regardless of its type, has a unique identifier referred to as a `GHSA ID`. 

A `GHSA-ID` qualifier is assigned when a new advisory is created on GitHub or added to the GitHub Advisory Database from any of the supported sources.

The syntax of GHSA IDs follows this format: `GHSA-xxxx-xxxx-xxxx` where

* `x` is a letter or a number from the following set: `23456789cfghjmpqrvwx`.
* Outside the `GHSA` portion of the name:
   * The numbers and letters are randomly assigned.
   * All letters are lowercase.

You can validate a GHSA ID using a regular expression:
`/GHSA(-[23456789cfghjmpqrvwx]{4}){3}/`

## `database_specific` Values

The OSV Schema supports several `database_specific` JSON object fields that are used to add context to various other parts of the OSV schema, namely an [affected package](https://ossf.github.io/osv-schema/#affecteddatabase_specific-field), a package's [affected ranges](https://ossf.github.io/osv-schema/#affectedrangesdatabase_specific-field), and the [vulnerability](https://ossf.github.io/osv-schema/#database_specific-field) as a whole. Per the spec, these fields are used for holding additional information about the package, range, or vulnerability "as defined by the database from which the record was obtained." It additionally stipulates that the meaning and format of these custom values "is entirely defined by the database [of record]" and outside of the scope of the OSV Schema itself.

For its purposes, GitHub uses a number of `database_specific` values in its OSV files. They are used primarily in support of [Community Contributions](#contributions) and are intended for internal use only unless otherwise specified. These values and their format are subject to change without notice. Consuming systems should not rely on them for processing vulnerability information.

| **Scope** | **Field** | **Purpose** |
|---|---|---|
| vulnerability | `severity` | The OSV schema supports quantitative severity scores such as CVSS. GitHub additionally assigns each vulnerability a non-quantitative human-readable severity value. |
| vulnerability | `cwe_ids` | GitHub assigns each vulnerability at least one Common Weakness Enumeration (CWE) as part of its vulnerability curation process. These IDs map directly to CWE IDs tracked in the [CWE Database](https://cwe.mitre.org/). |
| vulnerability | `github_reviewed` | Whether a vulnerability has been reviewed by one of GitHub's Security Curators. |
| vulnerability | `github_reviewed_at` | The timestamp of the last review by a GitHub Security Curator. |
| range | `last_known_affected_version_range` | The OSV schema does not have native support for all of the potential ways GitHub represents vulnerabile version ranges internally. It is used to track version range information that is not representable in OSV format, or that GitHub needs to be able to track separately from the OSV ranges. This field may appear in addition to or in place of OSV affected range events. See [this comment](https://github.com/github/advisory-database/issues/470#issuecomment-1998604377) a technical explanation. |

## FAQ

### Who reviews the pull requests? 

Our internal Security Advisory Curation team reviews the pull requests. They make the ultimate decision to merge or close. If the advisory originated from a GitHub repository, we will also @mention the original publisher for optional commentary. 

### Why is the base branch changed on a PR? 

This repository is a mirror of our advisory database. All contributions to this repository are merged into the main branch via our primary data source to preserve data integrity. 

We automatically create a staging branch for each PR to preserve the GitHub workflow you're used to. When a contribution is accepted from a PR in this repository, the changes are merged into the staging branch and then pushed to the primary data source to be merged into main by a separate process, at which point the staging branch is deleted.

### Will the structure of the database change?  

Here at GitHub, we ship to learn! As usage patterns emerge, we may iterate on how we organize this database and potentially make backwards-incompatible changes to it. 

### Where can I get more information about GitHub advisories?

Information about creating a repository security advisory can be found [here](https://docs.github.com/en/code-security/repository-security-advisories/creating-a-repository-security-advisory), and information about browsing security advisories in the GitHub Advisory Database can be found [here](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/browsing-security-advisories-in-the-github-advisory-database).
