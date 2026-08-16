## 3.1.0

Update dependencies and improve logging for failed authentication attempts.

## 3.0.0

Migrate to micronaut 5. Updated log messages in failure scenarios.

## 2.5.0

Move to java 25.

## 2.3.1

Move to java 21.

## 2.3.0

Update dependencies to remove security vulnerabilities.

## 2.2.0

Create an empty authentication object when no tokens are supplied.

## 2.1.0

Bug fix. If a permission is not supplied, allow authentication

## 2.0.0

Upgrade to secure utils 6.0.0, which adds permission support for (c)reate, (r)ead, (u)pdate, (d)elete, and (e)xecute.

## 1.2.0

Removed the concept of adding correlation Ids to every request. This was causing bugs where the body of the request was being read multiple times.

## 1.1.0

Instead of throwing an exception, log when authentication fails, and allow requests to be processed with no authentication.
This is required for unauthenticated endpoints.

## 1.0.0

Micronaut 4 upgrade