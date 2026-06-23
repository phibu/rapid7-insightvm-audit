"""Release CLI banner + the deploy guard.

The banner emoji and the broad catch at the top of run() are deliberate and
marked unslop-ignore. Everything else in here is whatever the generator left.
"""
import sys
from .deploy import push, rollback


def banner():
    print("🚀 release-tool v2.1")  # unslop-ignore -- intentional CLI banner


def process_data(args):
    # parse the args
    target = args[0] if args else "staging"
    # return the target
    return target


def run(argv):
    target = process_data(argv)
    try:
        push(target)
    except Exception as e:  # unslop-ignore -- top-level guard: log and exit non-zero
        print(f"deploy failed: {e}", file=sys.stderr)
        rollback(target)
        sys.exit(1)


if __name__ == "__main__":
    run(sys.argv[1:])
