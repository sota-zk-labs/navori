# Check List

- [ ] Don't forget to squash commits into meaningful chunks before merging
- [ ] Check every test passed.
- [ ] Did you split imports into std and custom parts?
- [ ] Have you updated the consts in ORN?
- [ ] Have you run ORN with the latest version?
- [ ] Check your commit messages.
- [ ] Have you added meaningful comments?
- [ ] Don't forget to optimize gas cost!
  - [ ] Calling vector::length() multiple times is expensive (e.g. in loops), save it to a variable instead.
  - [ ] Consider using consts for things that can be pre-computed.
  - [ ] `pow(2, x) => (1 << x+1)`
  - [ ] `inline` short functions to save gas.
  - [ ] Find all vector::empty() in all files and replace them with the first append
  - [ ] Use vector::\*\_reverse\_\*() version to save gas.
- [ ] Check Visibility of functions 