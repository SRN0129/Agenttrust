/**
 * Count-Min Sketch (Probabilistic Sub-Linear Frequency Estimator)
 *
 * Implements the Count-Min Sketch data structure (Cormode & Muthukrishnan).
 * Provides (ε, δ)-guaranteed frequency estimates of agent actions and resource access patterns
 * in strictly bounded O(1) memory, preventing denial-of-service and state exhaustion under high volume.
 */

export class CountMinSketch {
  private width: number;
  private depth: number;
  private table: Int32Array[];
  private hashSeeds: number[];
  private totalCount = 0;

  /**
   * @param epsilon Relative error tolerance (e.g. 0.01 = 1% error)
   * @param delta Error probability bound (e.g. 0.01 = 99% confidence)
   */
  constructor(epsilon: number = 0.01, delta: number = 0.01) {
    this.width = Math.max(16, Math.ceil(Math.E / epsilon));
    this.depth = Math.max(3, Math.ceil(Math.log(1.0 / delta)));

    this.table = [];
    for (let i = 0; i < this.depth; i++) {
      this.table.push(new Int32Array(this.width));
    }

    // Seed hash functions with distinct primes
    this.hashSeeds = [
      0x9e3779b9, 0x85ebca6b, 0xc2b2ae35, 0x27d4eb2f,
      0x165667b1, 0x1f83d9ab, 0x510e527f, 0x9b1e7f33
    ];
    while (this.hashSeeds.length < this.depth) {
      this.hashSeeds.push(Math.floor(Math.random() * 0x7fffffff));
    }
  }

  /**
   * Murmur-style 32-bit hash function.
   */
  private hash(key: string, seed: number): number {
    let h = seed ^ key.length;
    for (let i = 0; i < key.length; i++) {
      h = Math.imul(h ^ key.charCodeAt(i), 0x5bd1e995);
      h ^= h >>> 15;
    }
    return Math.abs(h) % this.width;
  }

  /**
   * Updates frequency count for a given key.
   */
  public add(key: string, count: number = 1): void {
    if (count <= 0) return;
    this.totalCount += count;

    for (let i = 0; i < this.depth; i++) {
      const idx = this.hash(key, this.hashSeeds[i]);
      this.table[i][idx] += count;
    }
  }

  /**
   * Returns the minimum upper-bound frequency estimate for the key.
   */
  public estimate(key: string): number {
    let minEstimate = Infinity;

    for (let i = 0; i < this.depth; i++) {
      const idx = this.hash(key, this.hashSeeds[i]);
      const val = this.table[i][idx];
      if (val < minEstimate) {
        minEstimate = val;
      }
    }

    return minEstimate === Infinity ? 0 : minEstimate;
  }

  public getTotalCount(): number {
    return this.totalCount;
  }

  public reset(): void {
    for (let i = 0; i < this.depth; i++) {
      this.table[i].fill(0);
    }
    this.totalCount = 0;
  }
}
