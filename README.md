# micronaut-security-utils
![Build](https://github.com/trevorism/micronaut-security-utils/actions/workflows/build.yml/badge.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/trevorism/micronaut-security-utils)
![GitHub language count](https://img.shields.io/github/languages/count/trevorism/micronaut-security-utils)
![GitHub top language](https://img.shields.io/github/languages/top/trevorism/micronaut-security-utils)

This library converts micronaut-security into using Trevorism JWT tokens.

Latest [Version](https://github.com/trevorism/micronaut-security-utils/releases/latest)

Controller methods with no `@Secure` annotations are available to all.

Controller methods with `@Secure` annotations conform to Trevorism authorization rules. See https://github.com/trevorism/secure-utils

## How to Build
`gradle clean build`