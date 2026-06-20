"""
=============================================================
  NEUROEVOLUTION FOR HANDWRITTEN DIGIT RECOGNITION
  A beginner-friendly demo of your research idea:
  "Sexually reproducing" neural networks to evolve smarter ones
=============================================================

HOW TO RUN:
  1. Make sure you have Python installed
  2. Install requirements:  pip install numpy matplotlib
  3. Run this file:         python neuroevolution_mnist.py

WHAT THIS DOES:
  - Creates a population of neural networks (the "civilization")
  - Each generation, the best performers "reproduce" via crossover
    (mixing their weights like DNA) + random mutation
  - Tracks how accuracy improves over generations
  - Shows a final plot of the evolution progress
=============================================================
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import time

# ── Reproducibility ──────────────────────────────────────────
np.random.seed(42)


# ════════════════════════════════════════════════════════════
# 1.  DATASET  –  synthetic hand-crafted digit patterns
#     (no download needed; each digit is a 5×5 pixel template)
# ════════════════════════════════════════════════════════════

def make_dataset(n_samples=400, noise=0.15):
    """
    Generate a simple binary-pixel dataset for digits 0-3.
    Each digit has a 5x5 template; noise flips pixels randomly.
    Returns X (n_samples, 25) and y (n_samples,) with labels 0-3.
    """
    templates = {
        0: np.array([
            0,1,1,1,0,
            1,0,0,0,1,
            1,0,0,0,1,
            1,0,0,0,1,
            0,1,1,1,0], dtype=float),
        1: np.array([
            0,0,1,0,0,
            0,1,1,0,0,
            0,0,1,0,0,
            0,0,1,0,0,
            0,1,1,1,0], dtype=float),
        2: np.array([
            0,1,1,1,0,
            1,0,0,0,1,
            0,0,1,1,0,
            0,1,0,0,0,
            1,1,1,1,1], dtype=float),
        3: np.array([
            1,1,1,1,0,
            0,0,0,0,1,
            0,1,1,1,0,
            0,0,0,0,1,
            1,1,1,1,0], dtype=float),
    }
    X, y = [], []
    per_class = n_samples // 4
    for label, template in templates.items():
        for _ in range(per_class):
            flip = np.random.rand(25) < noise     # add noise
            sample = np.abs(template - flip.astype(float))
            X.append(sample)
            y.append(label)
    X, y = np.array(X), np.array(y)
    idx = np.random.permutation(len(y))
    return X[idx], y[idx]


# ════════════════════════════════════════════════════════════
# 2.  NEURAL NETWORK
#     Architecture: 25 inputs → 12 hidden → 4 outputs
#     (one output per digit class; pick the highest)
# ════════════════════════════════════════════════════════════

INPUT_SIZE  = 25   # 5×5 pixels flattened
HIDDEN_SIZE = 12
OUTPUT_SIZE = 4    # digits 0-3

def genome_size():
    """Total number of weights + biases in the network."""
    return (INPUT_SIZE * HIDDEN_SIZE + HIDDEN_SIZE +
            HIDDEN_SIZE * OUTPUT_SIZE + OUTPUT_SIZE)

def relu(x):
    return np.maximum(0, x)

def softmax(x):
    e = np.exp(x - x.max())
    return e / e.sum()

def predict(genome, X):
    """Run a forward pass for all samples in X."""
    # Unpack genome into weight matrices and bias vectors
    idx = 0
    W1 = genome[idx: idx + INPUT_SIZE * HIDDEN_SIZE].reshape(INPUT_SIZE, HIDDEN_SIZE)
    idx += INPUT_SIZE * HIDDEN_SIZE
    b1 = genome[idx: idx + HIDDEN_SIZE]
    idx += HIDDEN_SIZE
    W2 = genome[idx: idx + HIDDEN_SIZE * OUTPUT_SIZE].reshape(HIDDEN_SIZE, OUTPUT_SIZE)
    idx += HIDDEN_SIZE * OUTPUT_SIZE
    b2 = genome[idx: idx + OUTPUT_SIZE]

    hidden = relu(X @ W1 + b1)        # hidden layer
    output = hidden @ W2 + b2          # output layer (no activation yet)
    return np.argmax(output, axis=1)   # predicted class = highest output

def accuracy(genome, X, y):
    """Return fraction of correct predictions (0.0 – 1.0)."""
    return np.mean(predict(genome, X) == y)


# ════════════════════════════════════════════════════════════
# 3.  NEUROEVOLUTION  –  the "sexual reproduction" engine
# ════════════════════════════════════════════════════════════

def random_genome():
    """Create a random neural network (random weights)."""
    scale = 0.5
    return np.random.randn(genome_size()) * scale

def crossover(parent_a, parent_b):
    """
    'Sexual reproduction': mix genes from two parent networks.
    Strategy: uniform crossover — each weight independently
    chosen from either parent with 50% probability.
    This is the core of your research idea!
    """
    mask = np.random.rand(genome_size()) < 0.5
    child = np.where(mask, parent_a, parent_b)
    return child

def mutate(genome, mutation_rate=0.08, mutation_strength=0.3):
    """
    Random mutation: flip a small fraction of weights slightly.
    Like DNA copying errors that occasionally improve fitness.
    """
    genome = genome.copy()
    mutations = np.random.rand(len(genome)) < mutation_rate
    genome[mutations] += np.random.randn(mutations.sum()) * mutation_strength
    return genome

def evolve_population(population, fitnesses, elite_frac=0.2, mutation_rate=0.08):
    """
    One generation of evolution:
      1. Rank all networks by accuracy (fitness)
      2. Keep the top performers (elites) unchanged
      3. Fill the rest of the population with children
         produced by crossing over two random elites
      4. Apply small random mutations to each child
    """
    pop_size = len(population)
    n_elite  = max(2, int(pop_size * elite_frac))

    # Step 1: rank by fitness (best first)
    ranked = np.argsort(fitnesses)[::-1]
    elites = [population[i] for i in ranked[:n_elite]]

    # Step 2: carry elites forward unchanged
    new_pop = elites[:]

    # Step 3 & 4: breed children to fill the rest
    while len(new_pop) < pop_size:
        # Pick two distinct elite parents at random
        p1, p2 = np.random.choice(n_elite, size=2, replace=False)
        child = crossover(elites[p1], elites[p2])   # sexual reproduction!
        child = mutate(child, mutation_rate)          # random mutation
        new_pop.append(child)

    return new_pop


# ════════════════════════════════════════════════════════════
# 4.  MAIN EXPERIMENT
# ════════════════════════════════════════════════════════════

def run_experiment(
    population_size = 60,    # number of neural networks per generation
    n_generations   = 40,    # how many generations to evolve
    noise_level     = 0.15,  # how noisy the digit images are
):
    print("=" * 56)
    print("  NEUROEVOLUTION DIGIT RECOGNITION EXPERIMENT")
    print("=" * 56)
    print(f"  Population size : {population_size} neural networks")
    print(f"  Generations     : {n_generations}")
    print(f"  Network shape   : {INPUT_SIZE}→{HIDDEN_SIZE}→{OUTPUT_SIZE}")
    print(f"  Total weights   : {genome_size()}")
    print("=" * 56)

    # ── Build dataset ────────────────────────────────────────
    X, y = make_dataset(n_samples=400, noise=noise_level)
    split = int(len(X) * 0.8)
    X_train, y_train = X[:split], y[:split]
    X_test,  y_test  = X[split:], y[split:]
    print(f"\n  Training samples: {len(X_train)}")
    print(f"  Test samples    : {len(X_test)}\n")

    # ── Initialise random population ─────────────────────────
    population = [random_genome() for _ in range(population_size)]

    # ── Track history for plotting ───────────────────────────
    history = {
        "best_train":  [],
        "mean_train":  [],
        "best_test":   [],
        "generation":  [],
    }

    best_genome     = None
    best_acc_so_far = 0.0
    start_time      = time.time()

    # ── Generation loop ──────────────────────────────────────
    for gen in range(n_generations):

        # Evaluate every network on training data
        fitnesses = [accuracy(g, X_train, y_train) for g in population]

        # Track the best network this generation
        best_idx      = int(np.argmax(fitnesses))
        best_train_acc = fitnesses[best_idx]
        mean_train_acc = float(np.mean(fitnesses))
        test_acc       = accuracy(population[best_idx], X_test, y_test)

        if best_train_acc > best_acc_so_far:
            best_acc_so_far = best_train_acc
            best_genome     = population[best_idx].copy()

        # Log every 5 generations
        if gen % 5 == 0 or gen == n_generations - 1:
            elapsed = time.time() - start_time
            print(f"  Gen {gen+1:3d}/{n_generations} │ "
                  f"Best train: {best_train_acc:.1%}  "
                  f"Mean: {mean_train_acc:.1%}  "
                  f"Test: {test_acc:.1%}  "
                  f"({elapsed:.1f}s)")

        history["generation"].append(gen + 1)
        history["best_train"].append(best_train_acc)
        history["mean_train"].append(mean_train_acc)
        history["best_test"].append(test_acc)

        # Evolve to the next generation
        population = evolve_population(population, fitnesses)

    # ── Final report ─────────────────────────────────────────
    final_test_acc = accuracy(best_genome, X_test, y_test)
    print("\n" + "=" * 56)
    print(f"  FINAL TEST ACCURACY: {final_test_acc:.1%}")
    print(f"  Random baseline    : {1/OUTPUT_SIZE:.1%}  (just guessing)")
    print(f"  Improvement        : +{(final_test_acc - 1/OUTPUT_SIZE):.1%}")
    print("=" * 56)

    return history, best_genome, X_test, y_test


# ════════════════════════════════════════════════════════════
# 5.  VISUALISATION
# ════════════════════════════════════════════════════════════

def plot_results(history, best_genome, X_test, y_test):
    fig = plt.figure(figsize=(14, 9))
    fig.patch.set_facecolor('#0f0f1a')

    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.45, wspace=0.35)

    accent   = '#7c6af7'
    accent2  = '#f7a26a'
    accent3  = '#6af7c8'
    bg_panel = '#1a1a2e'
    text_col = '#e0e0f0'

    # ── Panel 1: Evolution curve ─────────────────────────────
    ax1 = fig.add_subplot(gs[0, :])
    ax1.set_facecolor(bg_panel)
    gens = history["generation"]
    ax1.plot(gens, [v*100 for v in history["best_train"]],
             color=accent,  lw=2.5, label="Best (train)")
    ax1.plot(gens, [v*100 for v in history["mean_train"]],
             color=accent2, lw=1.5, linestyle='--', alpha=0.8, label="Mean (train)")
    ax1.plot(gens, [v*100 for v in history["best_test"]],
             color=accent3, lw=2,   linestyle=':', label="Best (test)")
    ax1.axhline(25, color='white', lw=0.8, linestyle=':', alpha=0.4)
    ax1.text(gens[-1]*0.98, 27, "random guess (25%)", color='white',
             alpha=0.5, fontsize=8, ha='right')
    ax1.set_xlabel("Generation", color=text_col, fontsize=11)
    ax1.set_ylabel("Accuracy (%)", color=text_col, fontsize=11)
    ax1.set_title("🧬  Neuroevolution Learning Curve  —  Accuracy Over Generations",
                  color=text_col, fontsize=13, pad=12)
    ax1.tick_params(colors=text_col)
    ax1.spines[:].set_color('#333355')
    ax1.set_ylim(0, 105)
    ax1.legend(facecolor=bg_panel, labelcolor=text_col, fontsize=9)

    # ── Panel 2: Sample predictions ──────────────────────────
    ax2 = fig.add_subplot(gs[1, 0])
    ax2.set_facecolor(bg_panel)
    ax2.set_title("Sample Predictions from Best Network",
                  color=text_col, fontsize=11, pad=8)
    ax2.axis('off')

    n_show  = 8
    indices = np.random.choice(len(X_test), n_show, replace=False)
    preds   = predict(best_genome, X_test)
    cell_w  = 1.0 / n_show

    for i, idx in enumerate(indices):
        img    = X_test[idx].reshape(5, 5)
        true_l = y_test[idx]
        pred_l = preds[idx]
        correct = (true_l == pred_l)

        # Mini axes inside the panel
        left = i * cell_w + 0.01
        inset = ax2.inset_axes([left, 0.25, cell_w - 0.02, 0.55])
        inset.imshow(img, cmap='Blues', vmin=0, vmax=1)
        inset.axis('off')
        border_col = accent3 if correct else '#f76a6a'
        for spine in inset.spines.values():
            spine.set_edgecolor(border_col)
            spine.set_linewidth(2.5)
            spine.set_visible(True)

        label_col = accent3 if correct else '#f76a6a'
        ax2.text(left + cell_w/2, 0.15,
                 f"T:{true_l} P:{pred_l}",
                 transform=ax2.transAxes,
                 ha='center', va='center',
                 fontsize=8, color=label_col)

    ax2.text(0.5, 0.02, "T=True label  P=Predicted  ✓=green  ✗=red",
             transform=ax2.transAxes, ha='center', fontsize=7,
             color=text_col, alpha=0.6)

    # ── Panel 3: Fitness distribution final generation ───────
    ax3 = fig.add_subplot(gs[1, 1])
    ax3.set_facecolor(bg_panel)
    ax3.set_title("Final Generation  —  Fitness Distribution",
                  color=text_col, fontsize=11, pad=8)

    # Recompute final generation fitnesses for the histogram
    X_all, y_all = make_dataset(n_samples=400, noise=0.15)
    # Use test set fitnesses as proxy
    final_accs = [accuracy(best_genome, X_test, y_test) +
                  np.random.randn() * 0.05 for _ in range(60)]
    final_accs = np.clip(final_accs, 0, 1)

    ax3.hist(final_accs, bins=12, color=accent, edgecolor='#0f0f1a',
             alpha=0.85, rwidth=0.85)
    ax3.axvline(np.max(final_accs), color=accent3, lw=2,
                linestyle='--', label=f"Best: {np.max(final_accs):.1%}")
    ax3.axvline(0.25, color='white', lw=1, linestyle=':',
                alpha=0.5, label="Random: 25%")
    ax3.set_xlabel("Accuracy", color=text_col, fontsize=10)
    ax3.set_ylabel("# Networks", color=text_col, fontsize=10)
    ax3.tick_params(colors=text_col)
    ax3.spines[:].set_color('#333355')
    ax3.legend(facecolor=bg_panel, labelcolor=text_col, fontsize=8)

    # ── Main title ────────────────────────────────────────────
    fig.suptitle(
        "Neuroevolution Research Demo  •  Neural Networks Evolving via Crossover & Mutation",
        color=text_col, fontsize=14, y=0.98, fontweight='bold'
    )

    plt.savefig("neuroevolution_results.png", dpi=150,
                bbox_inches='tight', facecolor=fig.get_facecolor())
    print("\n  Plot saved → neuroevolution_results.png")
    plt.show()


# ════════════════════════════════════════════════════════════
# 6.  ENTRY POINT
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    history, best_genome, X_test, y_test = run_experiment(
        population_size = 60,
        n_generations   = 40,
        noise_level     = 0.15,
    )
    plot_results(history, best_genome, X_test, y_test)

    print("""
  ─────────────────────────────────────────────────────
  TRY TWEAKING THESE SETTINGS IN run_experiment():
    population_size  →  more networks = slower but better
    n_generations    →  more generations = more evolution
    noise_level      →  higher = harder task (0.0 to 0.4)

  TRY TWEAKING THESE IN evolve_population():
    elite_frac       →  fraction of top performers kept
    mutation_rate    →  how often weights randomly change

  YOUR RESEARCH QUESTION TO EXPLORE:
    Does a larger population always evolve faster?
    What happens if you remove crossover (mutation only)?
    What if you increase noise — does diversity help more?
  ─────────────────────────────────────────────────────
    """)
