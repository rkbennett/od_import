# Contributing to od_import

All contributions are welcome: ideas, patches, documentation, bug reports,
complaints, etc!

## Feature Requests

* File a ticket on [GitHub](https://github.com/rkbennett/od_import/issues). Please remember that GitHub is used only for issues and feature requests.

## Bug reporting

If you think you found a bug, it probably is a bug.

* Feel free to create an issue so that we can investigate further
* Please provide the following information at a minimum:
```
Python Version: 3.10
Protocol used: http, ftp, smb
Code snippet: <you get the gist>
Platform: Windows 10
Errors (If any): <screen shots are fine>
```

# Contributing Documentation and Code Changes

Please note that Pull Requests without corresponding issues and documentation may not be merged.

## Contribution Steps

1. Test your changes!
2. If no issue/feature request exists please create one first.
3. Send a pull request! Push your changes to your fork of the repository and
   [submit a pull
   request](https://help.github.com/articles/using-pull-requests). In the pull
   request, describe what your changes do and mention the bugs/issues related
   to the pull request.
   
# Pull Request Guidelines

The following exists as a way to set expectations for yourself and for the review process. We *want* to merge fixes and features, so let's describe how we can achieve this:
   
## Goals

* To constantly make forward progress on PRs

* To have constructive discussions on PRs

## As a reviewee (i.e. author) of a PR:

* I must put up atomic PRs. This helps the reviewer of the PR do a high quality review fast. "Atomic" here means two things:
  - The PR must contain related changes and leave out unrelated changes (e.g. refactorings, etc. that could be their own PR instead).
  - If the PR could be broken up into two or more PRs either "vertically" (by separating concerns logically) or horizontally (by sharding the PR into a series of PRs --- usually works well with mass refactoring or cleanup type PRs), it should. A set of such related PRs can be tracked and given context in a meta issue.

* I must strive to please the reviewer(s). In other words, bias towards taking the reviewers suggestions rather than getting into a protracted argument. This helps move the PR forward. A convenient "escape hatch" to use might be to file a new issue for a follow up discussion/PR. If you find yourself getting into a drawn out argument, ask yourself: is this a good use of our time?

## As a reviewer of a PR:

* I must first focus on whether the PR works functionally -- i.e. does it solve the problem (bug, feature, etc.) it sets out to solve.

* Then I should ask myself: can I understand what the code in this PR is doing and, more importantly, why its doing whatever its doing, within 1 or 2 passes over the PR?

  * If yes, LGTM the PR!

  * If no, ask for clarifications on the PR. This will usually lead to changes in the code such as renaming of variables/functions or extracting of functions or simply adding "why" inline comments. But first ask the author for clarifications before assuming any intent on their part.

* I must not focus on personal preferences or nitpicks. If I understand the code in the PR but simply would've implemented the same solution a different way that's great but its not feedback that belongs in the PR. Such feedback only serves to slow down progress for little to no gain.