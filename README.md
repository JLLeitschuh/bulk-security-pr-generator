# Bulk Security Pull Request Generator

Used to generate bulk pull requests (PRs) against projects to fix security vulnerabilities.

These 'bulk fixes' are done as a part of the new [GitHub Security Lab](https://securitylab.github.com/) Bug Bounty Program.

Data is sourced from queries on [lgtm.com](https://lgtm.com) and used to target bulk pull-requests.

## Project 1: HTTPS Everywhere to Resolve Dependencies in Maven POM Files Everywhere! 

[![mitm_build](https://user-images.githubusercontent.com/1323708/59226671-90645200-8ba1-11e9-8ab3-39292bef99e9.jpeg)](https://medium.com/@jonathan.leitschuh/want-to-take-over-the-java-ecosystem-all-you-need-is-a-mitm-1fc329d898fb?source=friends_link&sk=3c99970c55a899ad9ef41f126efcde0e)

[Want to take over the Java ecosystem? All you need is a MITM!](https://medium.com/@jonathan.leitschuh/want-to-take-over-the-java-ecosystem-all-you-need-is-a-mitm-1fc329d898fb?source=friends_link&sk=3c99970c55a899ad9ef41f126efcde0e)

This project has been used to generate PRs that automatically fix a security vulnerability in Maven POM files that
are using HTTP instead of HTTPS to resolve dependencies.
