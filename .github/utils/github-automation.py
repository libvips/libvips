#!/usr/bin/env python3
#
# Originally from:
# https://github.com/llvm/llvm-project/blob/main/llvm/utils/git/github-automation.py
#
# Preserved license:
# ======- github-automation - LLVM GitHub Automation Routines--*- python -*--==#
#
# Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
# See https://llvm.org/LICENSE.txt for license information.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# ==-------------------------------------------------------------------------==#

import argparse
from git import Repo  # type: ignore
import github
import os
import re
import sys
from typing import List, Optional


def extract_commit_hash(arg: str):
    """
    Extract the commit hash from the argument passed to /action GitHub
    comment actions. We currently only support passing the commit hash
    directly or use the GitHub URL, such as
    https://github.com/libvips/libvips/commit/1a86d4e153536e035d1907652391a26f77cbe1b8
    """
    github_prefix = "https://github.com/libvips/libvips/commit/"
    if arg.startswith(github_prefix):
        return arg[len(github_prefix):]
    return arg


class BackportWorkflow:
    CHERRY_PICK_FAILED_LABEL = "cherry-pick-failed"

    """
    This class implements the sub-commands for the backport-workflow command.

    The execute_command method will automatically choose the correct sub-command
    based on the text in stdin.
    """

    def __init__(
        self,
        token: str,
        repo: str,
        issue_number: int,
        requested_by: str,
    ) -> None:
        self._token = token
        self._repo_name = repo
        self._issue_number = issue_number
        self._requested_by = requested_by

    @property
    def token(self) -> str:
        return self._token

    @property
    def repo_name(self) -> str:
        return self._repo_name

    @property
    def repo_owner(self) -> str:
        return self.repo_name.split("/")[0]

    @property
    def issue_number(self) -> int:
        return self._issue_number

    @property
    def requested_by(self) -> str:
        return self._requested_by

    @property
    def repo(self) -> github.Repository.Repository:
        return github.Github(auth=github.Auth.Token(self.token)).get_repo(
            self.repo_name
        )

    @property
    def issue(self) -> github.Issue.Issue:
        return self.repo.get_issue(self.issue_number)

    @property
    def push_url(self) -> str:
        return "https://github.com/{}".format(self.repo_name)

    @property
    def branch_name(self) -> str:
        return "issue{}".format(self.issue_number)

    @property
    def release_branch_for_issue(self) -> Optional[str]:
        issue = self.issue
        milestone = issue.milestone
        if milestone is None:
            return None
        #m = re.search("branch: (.+)", milestone.description)
        #if m:
        #    return m.group(1)
        return milestone.title

    def print_release_branch(self) -> None:
        print(self.release_branch_for_issue)

    def issue_notify_pull_request(self, pull: github.PullRequest.PullRequest) -> None:
        self.issue.create_comment(
            "/pull-request {}#{}".format(self.repo_name, pull.number)
        )

    def make_ignore_comment(self, comment: str) -> str:
        """
        Returns the comment string with a prefix that will cause
        a GitHub workflow to skip parsing this comment.

        :param str comment: The comment to ignore
        """
        return "<!--IGNORE-->\n" + comment

    def issue_notify_no_milestone(self, comment: List[str]) -> None:
        message = "{}\n\nError: Command failed due to missing milestone.".format(
            "".join([">" + line for line in comment])
        )
        self.issue.create_comment(self.make_ignore_comment(message))

    @property
    def action_url(self) -> str:
        if os.getenv("CI"):
            return "https://github.com/{}/actions/runs/{}".format(
                os.getenv("GITHUB_REPOSITORY"), os.getenv("GITHUB_RUN_ID")
            )
        return ""

    def issue_notify_cherry_pick_failure(
        self, commit: str
    ) -> github.IssueComment.IssueComment:
        message = self.make_ignore_comment(
            "Failed to cherry-pick: {}\n\n".format(commit)
        )
        action_url = self.action_url
        if action_url:
            message += action_url + "\n\n"
        message += "Please manually backport the fix and push it to your GitHub fork.  Once this is done, please create a [pull request](https://github.com/libvips/libvips/compare)"
        issue = self.issue
        comment = issue.create_comment(message)
        issue.add_to_labels(self.CHERRY_PICK_FAILED_LABEL)
        return comment

    def issue_notify_pull_request_failure(
        self, branch: str
    ) -> github.IssueComment.IssueComment:
        message = "Failed to create pull request for {} ".format(branch)
        message += self.action_url
        return self.issue.create_comment(message)

    def issue_remove_cherry_pick_failed_label(self):
        if self.CHERRY_PICK_FAILED_LABEL in [l.name for l in self.issue.labels]:
            self.issue.remove_from_labels(self.CHERRY_PICK_FAILED_LABEL)

    def get_main_commit(self, cherry_pick_sha: str) -> github.Commit.Commit:
        commit = self.repo.get_commit(cherry_pick_sha)
        message = commit.commit.message
        m = re.search(r"\(cherry picked from commit ([0-9a-f]+)\)", message)
        if not m:
            return None
        return self.repo.get_commit(m.group(1))

    def pr_request_review(self, pr: github.PullRequest.PullRequest):
        """
        This function will try to find the best reviewers for `commits` and
        then add a comment requesting review of the backport and add them as
        reviewers.

        The reviewers selected are those users who approved the pull request
        for the main branch.
        """
        reviewers = []
        for commit in pr.get_commits():
            main_commit = self.get_main_commit(commit.sha)
            if not main_commit:
                continue
            for pull in main_commit.get_pulls():
                for review in pull.get_reviews():
                    if review.state != "APPROVED":
                        continue
                    reviewers.append(review.user.login)
        if len(reviewers):
            message = "{} What do you think about merging this PR to the release branch?".format(
                " ".join(["@" + r for r in reviewers])
            )
            pr.create_issue_comment(message)
            pr.create_review_request(reviewers)

    def create_branch(self, commits: List[str]) -> bool:
        """
        This function attempts to backport `commits` into the branch associated
        with `self.issue_number`.

        If this is successful, then the branch is pushed to `self.repo_name`, if not,
        a comment is added to the issue saying that the cherry-pick failed.

        :param list commits: List of commits to cherry-pick.

        """
        print("cherry-picking", commits)
        branch_name = self.branch_name
        local_repo = Repo(".")
        local_repo.git.checkout(self.release_branch_for_issue)

        for c in commits:
            try:
                local_repo.git.cherry_pick("-x", c)
            except Exception as e:
                self.issue_notify_cherry_pick_failure(c)
                raise e

        push_url = self.push_url
        print("Pushing to {} {}".format(push_url, branch_name))
        local_repo.git.push(push_url, "HEAD:{}".format(branch_name), force=True)

        self.issue_remove_cherry_pick_failed_label()
        return self.create_pull_request(branch_name, commits)

    def check_if_pull_request_exists(
        self, repo: github.Repository.Repository, head: str
    ) -> bool:
        pulls = repo.get_pulls(head=head)
        return pulls.totalCount != 0

    def create_pull_request(
        self, branch: str, commits: List[str]
    ) -> bool:
        """
        Create a pull request in `self.repo_name`.  The base branch of the
        pull request will be chosen based on the milestone attached to the
        issue represented by `self.issue_number`  For example if the milestone
        is 8.18, then the base branch will be 8.18. `branch` will be used as
        the compare branch.
        https://docs.github.com/en/get-started/quickstart/github-glossary#base-branch
        https://docs.github.com/en/get-started/quickstart/github-glossary#compare-branch
        """
        repo = github.Github(auth=github.Auth.Token(self.token)).get_repo(
            self.repo_name
        )
        pull = None
        release_branch_for_issue = self.release_branch_for_issue
        if release_branch_for_issue is None:
            return False

        head = f"{self.repo_owner}:{branch}"
        if self.check_if_pull_request_exists(repo, head):
            print("PR already exists...")
            return True
        try:
            commit_message = repo.get_commit(commits[-1]).commit.message
            message_lines = commit_message.splitlines()
            title = "{}: {}".format(release_branch_for_issue, message_lines[0])
            body = "Backport {}\n\nRequested by: @{}".format(
                " ".join(commits), self.requested_by
            )
            pull = repo.create_pull(
                title=title,
                body=body,
                base=release_branch_for_issue,
                head=head,
                maintainer_can_modify=True,
            )

            pull.as_issue().edit(milestone=self.issue.milestone)

            # Once the pull request has been created, we can close the
            # issue that was used to request the cherry-pick
            self.issue.edit(state="closed", state_reason="completed")

            try:
                self.pr_request_review(pull)
            except Exception as e:
                print("error: Failed while searching for reviewers", e)

        except Exception as e:
            self.issue_notify_pull_request_failure(branch)
            raise e

        if pull is None:
            return False

        self.issue_notify_pull_request(pull)
        self.issue_remove_cherry_pick_failed_label()

        return True

    def execute_command(self) -> bool:
        """
        This function reads lines from STDIN and executes the first command
        that it finds.  The supported command is:
        /cherry-pick< ><:> commit0 <commit1> <commit2> <...>
        """
        for line in sys.stdin:
            line.rstrip()
            m = re.search(r"/cherry-pick\s*:? *(.*)", line)
            if not m:
                continue

            args = m.group(1)

            arg_list = args.split()
            commits = list(map(lambda a: extract_commit_hash(a), arg_list))
            return self.create_branch(commits)

        print("Do not understand input:")
        print(sys.stdin.readlines())
        return False

parser = argparse.ArgumentParser()
parser.add_argument(
    "--token", type=str, required=True, help="GitHub authentication token"
)
parser.add_argument(
    "--repo",
    type=str,
    default=os.getenv("GITHUB_REPOSITORY", "libvips/libvips"),
    help="The GitHub repository that we are working with in the form of <owner>/<repo> (e.g. libvips/libvips)",
)
parser.add_argument(
    "--issue-number", type=int, required=True, help="The issue number to update"
)
parser.add_argument(
    "--requested-by",
    type=str,
    required=True,
    help="The user that requested this backport",
)

args = parser.parse_args()

backport_workflow = BackportWorkflow(
    args.token,
    args.repo,
    args.issue_number,
    args.requested_by,
)
if not backport_workflow.release_branch_for_issue:
    backport_workflow.issue_notify_no_milestone(sys.stdin.readlines())
    sys.exit(1)
if not backport_workflow.execute_command():
    sys.exit(1)
