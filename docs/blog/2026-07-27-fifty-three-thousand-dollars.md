---
title: They spent $53,000 of your money to make $800
description: Somebody's AWS key walked off their laptop on a Tuesday afternoon. By Thursday morning it had run up a five-figure bill mining crypto. Here's how that night actually goes, start to finish.
date: 2026-07-27
track: threat-lens
---

# They spent $53,000 of your money to make $800

*Track: the threat lens · 2026-07-27 · ~6 min read*

> Quick note before we start. This didn't happen to one specific person - I
> stitched it together from a pile of documented incidents. Every dollar
> amount, file path, API call and timing below is real and sourced at the
> bottom. The developer is a stand-in. Everything that happens to them
> happened to somebody.

## 3:47 in the morning

Nobody's awake for this part.

First instance comes up in `us-east-1`. Then a few more. Then the
autoscaling group takes over and honestly the count stops mattering.

They're `c5a.24xlarge` boxes. Ninety-six vCPUs each - the kind of thing you
rent by the hour when you actually need it, and you think about it first.
Twenty minutes later there are instances running in five more regions.
`eu-west-1`. `ap-southeast-2`. Regions this account has never touched, that
the guy sleeping four time zones away has never opened in his life.

Then two more things happen, and this is where you can tell it's not an
amateur.

CloudWatch monitoring gets switched off on the new instances, so the graphs
stay nice and flat. And every single instance gets `disableApiTermination`
set to true.

Sit with that second one for a sec. It's a completely normal EC2 feature -
it's there so you don't accidentally nuke a production box. But set on
instances you *didn't launch*, it means that when you find these things in
the morning, you can't delete them. You have to go turn termination
protection off first. One instance at a time. In every region. While the
meter's running.

Someone reached into the account and took the off switch away.

## Then the bill shows up

This account normally runs $100, maybe $150 a month. Side project, couple
of small services. Nothing.

That month it was **$53,000**.

And here's the bit that actually gets me, from a nearly identical case - a
founder whose account got used the same way. The mining ran all night. It
burned **$45,000** of his money. The attackers walked away with about
**$800** of Monero.

Fifty-six bucks of your money for every dollar they make.

Think about what that means for a second. Nobody sized this up. Nobody
looked at his account, decided it was worth a night, picked a number.
Whatever grabbed the credential has no idea whose it was. Whatever spent it
doesn't either. There's no point in that whole chain where a human being
considers you at all. You didn't get robbed. You got processed.

## OK, so rewind. Tuesday, 2:14 PM

Thirty-six hours earlier.

He's trying to get a build green before a demo. Dependency needs bumping.
He runs `npm install`, it spits out the usual wall of text, build goes
green, he moves on with his day. Eleven seconds, start to finish.

And look - there was nothing to catch. I want to be clear about that,
because the instinct is to assume he was sloppy. He wasn't. There's no
version of that Tuesday where a careful person notices something. Nothing
looked wrong, because nothing *was* wrong on screen.

A postinstall hook ran. It read four files that were sitting in plaintext
right where every tool on earth expects to find them:

```
~/.aws/credentials
~/.ssh/id_ed25519
~/.npmrc
./.env
```

Zipped them, POSTed them somewhere. Four seconds, tops.

No exploit. No CVE. Nothing got escalated. A postinstall script runs as
you, and every one of those files is readable by you. That's it. That's the
whole trick, and it's been the whole trick forever.

## The ninety seconds after that

Here's what I think most people get wrong. You picture the credential
sitting in some database, waiting for a guy to eventually scroll past it.

Nope.

Honeypot people have been measuring this for years and it keeps getting
worse. Orca found exposed cloud secrets getting picked up and used within
about two minutes. Newer work from this May clocked the gap between
*harvest* and *first working API call* on stolen AWS keys at 30 to 105
seconds. Four out of six cases, under ninety seconds.

And it's the same six moves every time, in the same order:

```
identity check        who am I
policy read           what can I do
credential recovery   what else can I grab
role assumption       what can I become
bucket enumeration    what's in here
exfiltration          take it
```

That's not somebody poking around. That's a script that's run ten thousand
times. The line from the researcher stuck with me: *"This isn't
opportunism; it's automation and intent."*

So by 2:16 PM Tuesday - he's still in the same meeting - the account's
already been inventoried. The mining doesn't start until 3:47 AM Thursday
because that's a scheduling call, and it isn't his.

## Now here's the part that got me

AWS already built the fix for this. Genuinely, they did.

There's a managed policy called `AWSCompromisedKeyQuarantineV3`, and AWS
attaches it to your IAM user *automatically* when they spot one of your
keys loose out there. Strips out the permissions an attacker would need.
It's on version three. Which tells you everything, right? They've iterated
on this thing three times because it happens constantly enough to justify
building an assembly line for it.

It fires when they scan public code. GitHub commits, public repos - places
where a key becomes visible to everybody.

But this key was never public. It went laptop, zip file, HTTP POST,
attacker. It was never in a repo. No scanner is ever going to find it,
because there's nowhere to look.

So the net is real, and it works, and it's stretched over a completely
different hole. If your credential leaves your machine instead of your git
history, you go straight past it and never touch it.

## Alright, your turn

I'm not going to give you a command to run. Just four questions, and you
already know the answers:

Is `~/.aws/credentials` populated right this second, even though you're not
deploying anything?

How many `.env` files with real values are sitting in your project folders?
Not the ones you'd think of. The ones in directories you haven't opened
since March.

Is your SSH key actually passphrase-protected? Actually?

When did you last run `docker login`, and where do you reckon that
credential went?

Every yes is a file on a list that a postinstall hook reads in four
seconds. Not in theory. Those exact paths, in the incidents linked below.

## And the bill honestly isn't the bad part

The $53,000 mostly comes back. AWS usually waives fraud charges if you can
show a compromise and you moved fast. It's weeks of support tickets and
it's not guaranteed, but the money's the recoverable bit.

The rest isn't.

GitGuardian put out numbers in June: your average dev laptop is carrying
around **150 secrets**. Some machines run into the thousands. Cloud creds
are about 22% of them. Their CEO's line was that barely a week goes by now
without some major breach traced back to credentials pulled off a laptop.
When they measured the LiteLLM supply-chain thing, it had exposed **33,185
secrets across 6,943 machines**, and 3,760 of those were still working when
somebody counted.

So the same four seconds also took the GitHub token. The SSH key. The
`.env` with the production database URL in it. The session cookie that's
still logged into the company Slack.

Nobody invoices you for those. No weird spend, no support case, no
dashboard going red. The AWS charge is loud *because* it's the one part of
the theft that costs the attacker money to use. The rest is quiet.

Quiet isn't the same as fine. You'll probably never find out which of them
got used.

## What I do about it

I build [jit](https://github.com/jitpass/jit), so take this with however
much salt you like.

The idea's pretty narrow: those files shouldn't be sitting there in
plaintext when you're not using them. jit moves each credential into an
encrypted vault and rewrites the file so your tools keep working -
`~/.aws/credentials` turns into a `credential_process` line, a `.env` shows
decoys until something legitimately asks for the real thing. That
postinstall script reading its four files gets a config pointer and some
fake values.

It won't stop the package from running. It doesn't make you unstealable,
and I've written up the [honest limits](../security/architecture.md)
elsewhere. All it changes is what's lying around when something comes
looking.

`jit scan` is read-only, writes nothing, and answers those four questions
for you in about a minute. That's the whole pitch. And you genuinely don't
need it to act on any of this - `chmod`, short-lived creds, and
`--ignore-scripts` are all real answers too.

But go answer the four questions tonight. Whatever tool you feel like
using. The guy in this story answered them on a Thursday morning with a
$53,000 invoice open in the next tab, and by then they weren't really
questions anymore. Just paperwork.

---

*Next in the threat lens: your `.npmrc` is a bearer token - how one
plaintext line turned into a self-replicating supply chain attack.*

### Sources

- [Cloud account takeover: from leaked AWS keys to crypto mining in 4 minutes](https://blog.it-learn.io/posts/2026-04-21-cloud-account-takeover-leaked-aws-keys-crypto-mining/)
- [$45,000 AWS crypto-mining hack generates $800 of Monero - Tom's Hardware](https://www.tomshardware.com/news/aws-45000-usd-bill-for-crypto-mining-hack)
- [An Amazon crypto scam left its victim with a $45,000 bill - Digital Trends](https://www.digitaltrends.com/computing/aws-monero-hack-45000-dollars/)
- [Orca Security 2023 Honeypotting in the Cloud Report](https://www.businesswire.com/news/home/20230620120939/en/Orca-Security-2023-Honeypotting-in-the-Cloud-Report-Reveals-Attackers-Weaponize-Exposed-Cloud-Secrets-in-as-Little-as-Two-Minutes)
- [From leaked AWS key to data exfiltration in 60 seconds](https://medium.com/@adan.alvarez/from-leaked-aws-key-to-data-exfiltration-in-60-seconds-are-we-ready-28213bc73678)
- [CloudKeys in the Air: tracking malicious operations of exposed IAM keys - Unit 42](https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/)
- [AWSCompromisedKeyQuarantineV3 - AWS managed policy reference](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html)
- [Developer laptops are the credential store attackers are picking through in 2026 - GitGuardian](https://securityledger.com/2026/06/developer-laptops-are-the-credential-store-attackers-are-picking-through-in-2026-gitguardian-announces-endpoint-protection/)
- [How LiteLLM turned developer machines into credential vaults for attackers - The Hacker News](https://thehackernews.com/2026/04/how-litellm-turned-developer-machines.html)
