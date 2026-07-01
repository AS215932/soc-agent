"""SOC commander LangGraph runtime: route a finding to a security specialist,
enrich/validate it, gate on human approval, and terminate at an LHP handoff
request. There is no execution node — the SOC Agent never mutates production."""
