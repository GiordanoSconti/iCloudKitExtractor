// DFRWS / Forensic Science International: Digital Investigation–inspired layout.
// Single-column A4 so sequence diagrams and wide tables stay readable.

#let journal-blue = rgb("#003366")
#let rule-gray = luma(110)
#let soft-gray = luma(246)

#set page(
  paper: "a4",
  margin: (left: 2.0cm, right: 2.0cm, top: 2.35cm, bottom: 2.15cm),
  header: context {
    if counter(page).get().first() > 1 {
      set text(size: 8pt, fill: rule-gray)
      grid(
        columns: (1fr, auto),
        align: (left, right),
        [G. Sconti / From GrandSlam to MMCS],
        [Whitepaper 1.11],
      )
      v(3pt)
      line(length: 100%, stroke: 0.4pt + rule-gray)
    }
  },
  footer: context {
    set text(size: 8pt, fill: rule-gray)
    line(length: 100%, stroke: 0.4pt + rule-gray)
    v(4pt)
    grid(
      columns: (1fr, auto),
      align: (left, right),
      [Digital forensics · Apple iCloud protocols],
      counter(page).display("1"),
    )
  },
)

#set text(font: "New Computer Modern", size: 10pt, lang: "en", hyphenate: true)
#set par(justify: true, leading: 0.62em)
#set heading(numbering: none)

#show raw: set text(size: 7.8pt, font: "DejaVu Sans Mono")
#show figure: set block(breakable: true)
#show figure.caption: set text(size: 9pt)
#show table: set text(size: 8.0pt)
#set table(
  stroke: 0.45pt + luma(160),
  inset: (x: 4.2pt, y: 3.2pt),
)
#show raw.where(block: false): it => {
  box({
    set text(size: 7.6pt)
    it
  })
}
#show link: set text(fill: rgb("#0b5a7a"))

#show heading.where(level: 1): it => {
  let r = repr(it.body)
  let is-appendix = r.contains("Appendix") or r.contains("Appendice")
  if is-appendix {
    pagebreak(weak: true)
    v(0.6em)
    block({
      set text(size: 12.5pt, weight: "bold")
      it.body
    })
    v(0.45em)
  } else {
    // Masthead + title (Elsevier / DFRWS first page)
    block(width: 100%, {
      set text(size: 8pt, fill: journal-blue)
      text(weight: "bold")[Technical whitepaper · Digital forensics]
      linebreak()
      text(size: 7.4pt, fill: rule-gray)[
        Scope: GrandSlam → Escrow/PCS → Octagon/CKKS → CloudKit mbksync → MMCS/PCSMMCS2
      ]
      v(5pt)
      line(length: 100%, stroke: 1.15pt + journal-blue)
      v(11pt)
      set text(size: 14.5pt, weight: "bold", fill: black, hyphenate: false)
      set par(leading: 0.92em, justify: false)
      it.body
      v(6pt)
      line(length: 40%, stroke: 0.6pt + rule-gray)
    })
  }
}

#show heading.where(level: 2): it => {
  let is-abs = {
    let r = repr(it.body)
    r.contains("Abstract") or r.contains("Sommario")
  }
  if is-abs {
    v(0.85em)
    block(
      width: 100%,
      fill: soft-gray,
      inset: (x: 8pt, y: 7pt),
      stroke: 0.45pt + luma(175),
      {
        set text(size: 7.7pt)
        set par(leading: 0.55em, justify: false)
        text(weight: "bold", size: 8.5pt)[ARTICLE INFO]
        h(10pt)
        text(weight: "bold")[Type:]
        [ Technical whitepaper]
        h(10pt)
        text(weight: "bold")[Date:]
        [ 16 Nov 2026]
        h(10pt)
        text(weight: "bold")[Version:]
        [1.11]
        v(4pt)
        text(weight: "bold")[Keywords:]
        [ Mobile forensics; Cloud acquisition; iCloud backup; GrandSlam;
          EscrowProxy; Octagon; CKKS; Manatee; MMCS; ADP]
      },
    )
    v(0.7em)
    block({
      set text(size: 10pt, weight: "bold")
      [ABSTRACT]
    })
    v(0.25em)
    line(length: 100%, stroke: 0.35pt + rule-gray)
    v(0.35em)
  } else {
    v(1.05em)
    block({
      set text(size: 11pt, weight: "bold")
      set par(first-line-indent: 0pt)
      it.body
    })
    v(0.3em)
  }
}

#show heading.where(level: 3): it => {
  v(0.8em)
  block({
    set text(size: 10pt, weight: "bold")
    it.body
  })
  v(0.22em)
}

#show heading.where(level: 4): it => {
  v(0.6em)
  block({
    set text(size: 9.5pt, weight: "bold", style: "italic")
    it.body
  })
  v(0.18em)
}
