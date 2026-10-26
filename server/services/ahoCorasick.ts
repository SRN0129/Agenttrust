/**
 * Aho-Corasick Deterministic Finite Automaton (DFA)
 *
 * Implements the linear-time Aho-Corasick multi-pattern string matching automaton.
 * Scans streaming input text in O(n + z) time regardless of pattern count,
 * replacing exponential backtracking regexes with a mathematically deterministic state machine.
 */

export interface PatternMatch {
  pattern: string;
  tag: string;
  startIndex: number;
  endIndex: number;
}

class TrieNode {
  public children: Map<string, TrieNode> = new Map();
  public failure: TrieNode | null = null;
  public outputs: Array<{ pattern: string; tag: string }> = [];

  constructor(public id: number, public depth: number = 0) {}
}

export class AhoCorasickAutomaton {
  private root: TrieNode;
  private nodeCount = 0;
  private built = false;

  constructor() {
    this.root = new TrieNode(this.nodeCount++);
  }

  /**
   * Adds a keyword or substring pattern into the Trie.
   */
  public addPattern(pattern: string, tag: string = "INJECTION_TRIGGER"): void {
    if (!pattern || pattern.length === 0) return;
    this.built = false;

    let current = this.root;
    const lowerPattern = pattern.toLowerCase();

    for (let i = 0; i < lowerPattern.length; i++) {
      const char = lowerPattern[i];
      let child = current.children.get(char);
      if (!child) {
        child = new TrieNode(this.nodeCount++, current.depth + 1);
        current.children.set(char, child);
      }
      current = child;
    }

    current.outputs.push({ pattern, tag });
  }

  /**
   * Constructs failure links and dictionary output links using Breadth-First Search (BFS).
   */
  public build(): void {
    const queue: TrieNode[] = [];

    // Root children have failure links pointing to root
    for (const child of this.root.children.values()) {
      child.failure = this.root;
      queue.push(child);
    }

    // BFS through the Trie
    while (queue.length > 0) {
      const current = queue.shift()!;

      for (const [char, child] of current.children.entries()) {
        queue.push(child);

        let failureCandidate = current.failure;
        while (failureCandidate !== null && !failureCandidate.children.has(char)) {
          failureCandidate = failureCandidate.failure;
        }

        if (failureCandidate === null) {
          child.failure = this.root;
        } else {
          const matchNode = failureCandidate.children.get(char)!;
          child.failure = matchNode;
          // Merge output matches from the failure link node
          child.outputs = child.outputs.concat(matchNode.outputs);
        }
      }
    }

    this.built = true;
  }

  /**
   * Scans input text and returns all matching patterns in linear time.
   */
  public search(text: string): PatternMatch[] {
    if (!this.built) {
      this.build();
    }

    const matches: PatternMatch[] = [];
    if (!text || text.length === 0) return matches;

    const lowerText = text.toLowerCase();
    let current = this.root;

    for (let i = 0; i < lowerText.length; i++) {
      const char = lowerText[i];

      // Follow failure transitions if child does not exist
      while (current !== this.root && !current.children.has(char)) {
        current = current.failure ?? this.root;
      }

      current = current.children.get(char) ?? this.root;

      // Collect any matched outputs at this node
      if (current.outputs.length > 0) {
        for (const out of current.outputs) {
          matches.push({
            pattern: out.pattern,
            tag: out.tag,
            startIndex: i - out.pattern.length + 1,
            endIndex: i + 1,
          });
        }
      }
    }

    return matches;
  }
}
