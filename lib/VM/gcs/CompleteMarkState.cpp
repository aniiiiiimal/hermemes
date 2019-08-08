/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the LICENSE
 * file in the root directory of this source tree.
 */
#include "hermes/VM/CompleteMarkState.h"
#include "hermes/VM/CompleteMarkState-inline.h"
#include "hermes/VM/GCBase-inline.h"
#include "hermes/VM/GCBase.h"

namespace hermes {
namespace vm {

void CompleteMarkState::markTransitive(void *ptr) {
  if (markingVarSizeCell &&
      numPtrsPushedByParent == kMaxPtrsPushedByVarParent) {
    return;
  }

  MarkBitArrayNC *markBits = AlignedHeapSegment::markBitArrayCovering(ptr);
  size_t ind = markBits->addressToIndex(ptr);

  assert(ind < markBits->size());

  // If the object is already marked, nothing to do.
  if (markBits->at(ind)) {
    return;
  }

  // Setting the mark bit, with the assumption that if overflow
  // occurs, the "cursor" in the higher-level process that's calling
  // this to reach transitive closure will be reset, and the
  // transitive closure process restarted. See, e.g., GenGC::completeMarking.
  markBits->mark(ind);

  // By only pushing ptrs that point back down the heap and leaving
  // others to be fully marked later, potential size of markStack_
  // lowers. Note that there's no check for equal indices since
  // markBits->at(currentBitmapIndex_) must be true at this line, which
  // wouldn't make it past the earlier check for a false value if the
  // indices were equal.
  if (ptr < reinterpret_cast<void *>(currentParPointer)) {
    GCCell *cell = reinterpret_cast<GCCell *>(ptr);
    // Push cell to the correct mark stack.
    std::vector<GCCell *> *stack =
        (cell->isVariableSize() ? &varSizeMarkStack_ : &markStack_);
    if (stack->size() == kMarkStackLimit) {
      markStackOverflow_ = true;
    } else {
      stack->push_back(cell);
      numPtrsPushedByParent++;
    }
  }
}

void CompleteMarkState::drainMarkStack(
    GC *gc,
    FullMSCMarkTransitiveAcceptor &acceptor) {
  while (!markStack_.empty() || !varSizeMarkStack_.empty()) {
    GCCell *cell;
    if (markStack_.size() >= varSizeMarkStack_.size()) {
      cell = markStack_.back();
      markStack_.pop_back();
      markingVarSizeCell = false;
    } else {
      cell = varSizeMarkStack_.back();
      markingVarSizeCell = true;
    }
    // Zeroing out this variable is only useful for var sized cells and could be
    // skipped for fixed sized cells.
    numPtrsPushedByParent = 0;

    GCBase::markCell(cell, gc, acceptor);

    // All fields of a fixed-sized cell should be marked by this point, but var
    // sized GCCells may not. Pop if the last round of marking pushed nothing,
    // meaning the cell has been fully marked.
    if (markingVarSizeCell && numPtrsPushedByParent == 0) {
      varSizeMarkStack_.pop_back();
    }
  }
}

std::unique_ptr<FullMSCUpdateAcceptor> getFullMSCUpdateAcceptor(GC &gc) {
  return std::unique_ptr<FullMSCUpdateAcceptor>(new FullMSCUpdateAcceptor(gc));
}

} // namespace vm
} // namespace hermes
