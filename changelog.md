## 2.0.0

Upgrade to secure utils 6.0.0, which adds permission support for (c)reate, (r)ead, (u)pdate, (d)elete, and (e)xecute.

## 1.2.0

Removed the concept of adding correlation Ids to every request. This was causing bugs where the body of the request was being read multiple times.

## 1.1.0

Instead of throwing an exception, log when authentication fails, and allow requests to be processed with no authentication.
This is required for unauthenticated endpoints.

## 1.0.0

Micronaut 4 upgrade