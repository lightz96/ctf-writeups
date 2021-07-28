# Hidden

## Challenge Description: 
`Oh no, someone hid my flag behind a giant red block! Please help me retrieve it!!`

## Solution
The first command that I always ran is `strings`

```bash
$ strings 10C4-challenge.psd | grep -i ictf
ictf{wut_how_do_you_see_this}
```

Flag: `ictf{wut_how_do_you_see_this}`