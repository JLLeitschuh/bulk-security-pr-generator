[SECURITY] Use HTTPS to resolve dependencies in Maven Build

[![mitm_build](https://user-images.githubusercontent.com/1323708/59226671-90645200-8ba1-11e9-8ab3-39292bef99e9.jpeg)](https://medium.com/@jonathan.leitschuh/want-to-take-over-the-java-ecosystem-all-you-need-is-a-mitm-1fc329d898fb?source=friends_link&sk=3c99970c55a899ad9ef41f126efcde0e)

- [Want to take over the Java ecosystem? All you need is a MITM!](https://medium.com/@jonathan.leitschuh/want-to-take-over-the-java-ecosystem-all-you-need-is-a-mitm-1fc329d898fb?source=friends_link&sk=3c99970c55a899ad9ef41f126efcde0e)
- [Update: Want to take over the Java ecosystem? All you need is a MITM!](https://medium.com/bugbountywriteup/update-want-to-take-over-the-java-ecosystem-all-you-need-is-a-mitm-d069d253fe23?source=friends_link&sk=8c8e52a7d57b98d0b7e541665688b454)

---

This is a security fix for a  vulnerability in your [Apache Maven](https://maven.apache.org/) `pom.xml` file(s).

The build files indicate that this project is resolving dependencies over HTTP instead of HTTPS.
This leaves your build vulnerable to allowing a [Man in the Middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) (MITM) attackers to execute arbitrary code on your or your computer or CI/CD system.

This vulnerability has a CVSS v3.0 Base Score of [8.1/10](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

## This isn't just theoretical

POC code has existed since 2014 to maliciously compromise a JAR file in-flight.

See:
* https://max.computer/blog/how-to-take-over-the-computer-of-any-java-or-clojure-or-scala-developer/
* https://github.com/mveytsman/dilettante

## MITM Attacks Increasingly Common

See:
* https://serverfault.com/a/153065
* https://security.stackexchange.com/a/12050
* [Comcast continues to inject its own code into websites you visit](https://thenextweb.com/insights/2017/12/11/comcast-continues-to-inject-its-own-code-into-websites-you-visit/#) (over HTTP)


## Why are you contributing here?

I'm an open-source security researcher who values the supply chain security for the JVM ecosystem.

I contributed this PR to your project as a way to fix this industry-wide security vulnerability facing our ecosystem.

This contribution is a part of a submission to the [GitHub Security Lab](https://securitylab.github.com/) Bug Bounty program.

## Detecting this and Future Vulnerabilities

This vulnerability was automatically detected by [LGTM.com](https://lgtm.com) using this [CodeQL Query](https://lgtm.com/rules/1511115648721/).

As of September 2019 LGTM.com and Semmle are [officially a part of GitHub](https://github.blog/2019-09-18-github-welcomes-semmle/).

You can automatically detect future vulnerabilities like this by enabling the free (for open-source) [LGTM App](https://github.com/marketplace/lgtm).

I'm not an employee of GitHub nor of Semmle, I'm simply a user of [LGTM.com](https://lgtm.com) and an open-source security researcher.

## Source

Yes, this contribution was automatically generated, however, the code to generate this PR was lovingly hand crafted to bring this security fix to your repository.

The source code that generated and submitted this PR can be found here:
[JLLeitschuh/bulk-security-pr-generator](https://github.com/JLLeitschuh/bulk-security-pr-generator)

## Opting-Out

If you'd like to opt-out of future automated security vulnerability fixes like this, please consider adding a file called
`.github/GH-ROBOTS.txt` to your repository with the line:

```
User-agent: JLLeitschuh/bulk-security-pr-generator
Disallow: *
```

This bot will respect the [ROBOTS.txt](https://moz.com/learn/seo/robotstxt) format for future contributions.

Alternatively, if this project is no longer actively maintained, consider [archiving](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/about-archiving-repositories) the repository.
