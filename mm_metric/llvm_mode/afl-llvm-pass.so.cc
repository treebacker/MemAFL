/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../../config.h"
#include "../../debug.h"

#include <fstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <algorithm>
#include <vector>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/Constants.h"

using namespace llvm;

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      StringRef getPassName() const override {
         return "American Fuzzy Lop Instrumentation";
      }

  };

}

std::vector<std::string> block_int_strings = {
  "got", "bss", "data", "text", "comment", "start",
  "fini_array", "init_array", "note", "rodata",
  "plt", "sym", "gotoff", "file", "debug",
};

std::vector<std::string> string_routines = {
  // string operation
  "strcpy",  "strncpy",  "strerror", "strlen",
  "strcat",  "strncat",  "strcmp",   "strspn",
  "strcoll", "strncmp",  "strxfrm",  "strstr",
  "strchr",  "strcspn",  "strpbrk",  "strrchr", 
  "strtok",  "strdup",
  "memchr", "memcmp", "memcpy", 
  // TODO... add more interesting functions
};

std::vector<std::string> memory_routines = {
  // string operation
  "strcpy",  "strncpy",  "strerror", "strlen",
  "strcat",  "strncat",  "strcmp",   "strspn",
  "strcoll", "strncmp",  "strxfrm",  "strstr",
  "strchr",  "strcspn",  "strpbrk",  "strrchr", 
  "strtok",  "strdup",
  // memory allocation
  "alloca", "calloc",  "malloc",   "realloc",  "free", 
  // memory operation
  "memcmp", "memcpy",  "memmove",  "memchr",   
  "memset",  
};

bool is_memory_function(std::string fn_name)
{
  for(std::vector<std::string>::size_type i = 0; i < memory_routines.size(); i++){
    if(fn_name.compare(0, memory_routines[i].size(), memory_routines[i]) == 0)
      return true;
  }
  return false;
}

bool is_string_routines(std::string fn_name)
{
  for(std::vector<std::string>::size_type i = 0; i < string_routines.size(); i++) {
    if(fn_name.compare(0, string_routines[i].size(), string_routines[i]) == 0)
      return true;
  }
  return false;
}

bool is_block_string(std::string bstr)
{
    for(std::vector<std::string>::size_type i = 0; i < block_int_strings.size(); i++) {
    if(bstr.find(block_int_strings[i]) != std::string::npos)
      return true;
  }
  return false;
}

void saveInterestingString(Module &M)
{
  std::vector<std::string> global_str;
  std::vector<std::string> interesting_str;

  for (GlobalVariable &GVar : M.globals()) {
    if (!GVar.hasInitializer())
      continue;
    // Unwrap the global variable to receive its value
    Constant *Initializer = GVar.getInitializer();

    if (isa<ConstantDataArray>(Initializer))
    {
      auto CDA = cast<ConstantDataArray>(Initializer);
      if (!CDA->isString())
        continue;
      std::string tstr = CDA->getAsString().str();
      if(tstr.length() < 3 || is_block_string(tstr))         // length 
        continue;
      global_str.push_back(tstr);
    }

    // Find all user
    for (User *Usr : GVar.users()) {
      if(Usr == nullptr)
        continue;
      Instruction *Inst = dyn_cast<Instruction>(Usr);
      if (Inst == nullptr) {
        // If Usr is not an instruction, like i8* getelementptr...
        // Dig deeper to find Instruction.
        for (User *DirecUsr : Usr->users()) {
          if(DirecUsr == nullptr)
            continue;
          Inst = dyn_cast<Instruction>(DirecUsr);
          if (Inst == nullptr) {
            continue;
          }
        }
      }
      if(Inst == nullptr)
        continue;

      // find next until call instruction
      while(!isa<CallInst>(Inst))
      {
        Instruction* tinst;
        tinst = Inst->getNextNonDebugInstruction();
        if(tinst == nullptr)
          break;
        Inst = tinst;
      }

      if(!isa<CallInst>(Inst))
        continue;

      auto* call_inst = dyn_cast_or_null<CallInst>(Inst);
      Function* fn = call_inst->getCalledFunction();
      if(fn == NULL){
        Value *v = call_inst->getCalledValue();
        fn = dyn_cast<Function>(v->stripPointerCasts());
        if(fn == NULL)
          continue;
      }
      std::string fn_name = fn->getName();
      if(fn_name.compare(0, 5, "llvm.") == 0)
        continue;
      if(is_string_routines(fn_name))
      {
        if (global_str.empty()) continue;

        interesting_str.push_back(global_str.back());
      }
      
    }
  }

  if (interesting_str.empty()) return;
  // sort & unique
  std::sort(interesting_str.begin(), interesting_str.end());
  interesting_str.erase(unique(interesting_str.begin(), interesting_str.end()), interesting_str.end());

  // save in file
  if(interesting_str.size())
  {
    std::ofstream fp;
    fp.open("./interesting.txt", std::ios::app);
    for(int i=0; i < interesting_str.size(); i++)
    {
      fp << interesting_str[i] << std::endl;
    }

    fp.close();
  }
}

char AFLCoverage::ID = 0;
bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLMemFuncPtr = 
      new GlobalVariable(M, PointerType::get(Int32Ty, 0), false, 
                        GlobalVariable::ExternalLinkage, 0, "__afl_memfunc_ptr");

  GlobalVariable *AFLMemReadWritePtr = 
      new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
                        GlobalValue::ExternalLinkage, 0, "__afl_memreadwrite_ptr");

  GlobalVariable *AFLCallPtr = 
      new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
                        GlobalValue::ExternalLinkage, 0, "__afl_call_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
      
     

  saveInterestingString(M);
  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M)
  {
    int b_cnt = 0;
    int exit_cnt = 0;  //

    // count exit blocks in the function
    for(auto &BB : F){
    if(strstr(BB.getTerminator()->getOpcodeName(), "ret") ||
        strstr(BB.getTerminator()->getOpcodeName(), "unreachable"))
        exit_cnt ++;
    }

    for (auto &BB : F) {
      // skip first block 
      b_cnt ++;
      if(b_cnt == 1)
        continue;

      // skip last block which function has only one.
      if(exit_cnt == 1 && strstr(BB.getTerminator()->getOpcodeName(), "ret"))
        continue;

      int mem_func_cnt = 0;
      int mem_readwrite_cnt = 0;
      int call_cnt = 0;

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));    // all insert starts After IP

      if (AFL_R(100) >= inst_ratio) continue;

      // search memory operation
      for(auto Inst = BB.begin(); Inst != BB.end(); Inst++){

        /*
        Insert an instruction
        */
        //BinaryOperator bo = cast<BinaryOperator>(inst);
        Instruction &inst = *Inst;
        if(inst.getOpcode() == Instruction::Add){
          inst.dump();
        }
        if(CallInst* call_inst = dyn_cast<CallInst>(&inst)) {
          Function* fn = call_inst->getCalledFunction();
          if(fn == NULL)
          {
            Value *v = call_inst->getCalledValue();
            fn = dyn_cast<Function>(v->stripPointerCasts());
            if(fn == NULL)
              continue;
          }
          std::string fn_name = fn->getName();
          if(fn_name.compare(0, 5, "llvm.") == 0)
            continue;
          if(is_memory_function(fn_name)){
            mem_func_cnt++;
          }
        }

        if(inst.mayReadFromMemory() || inst.mayWriteToMemory()){
          mem_readwrite_cnt++;
        }
      
        if(strstr(inst.getOpcodeName(), "call"))
        {
          call_cnt++;
        }

      }

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);   // a random int as cur_loc

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /*Load and update memory function map*/
      if(mem_func_cnt > 0)
      {
        LoadInst *MemoryPtr = IRB.CreateLoad(AFLMemFuncPtr);
        MemoryPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value* MemoryPtrIdx = IRB.CreateGEP(MemoryPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        LoadInst *MemoryCounter = IRB.CreateLoad(MemoryPtrIdx);
        MemoryCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MemoryIncr = IRB.CreateAdd(MemoryCounter, ConstantInt::get(Int32Ty, mem_func_cnt));
        IRB.CreateStore(MemoryIncr, MemoryPtrIdx)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }
      
      // Load and update mem read/write map
      // MemReadCount += mem_read_cnt
      if(mem_readwrite_cnt > 0){

          LoadInst *MemReadPtr = IRB.CreateLoad(AFLMemReadWritePtr);
          MemReadPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          // 也是根据Prevloc ^ CurLoc 设置MemPtr
          Value *MemReadPtrIdx = IRB.CreateGEP(MemReadPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

          LoadInst *MemReadCount = IRB.CreateLoad(MemReadPtrIdx);
          MemReadCount->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          // 累加
          Value *MemReadIncr = IRB.CreateAdd(MemReadCount, ConstantInt::get(Int32Ty, mem_readwrite_cnt));
          IRB.CreateStore(MemReadIncr, MemReadPtrIdx)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      }

      if(call_cnt > 0) {

          LoadInst *MemCallPtr = IRB.CreateLoad(AFLCallPtr);
          MemCallPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          // 也是根据Prevloc ^ CurLoc 设置MemPtr
          Value *MemCallPtrIdx = IRB.CreateGEP(MemCallPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

          LoadInst *MemCallCount = IRB.CreateLoad(MemCallPtrIdx);
          MemCallCount->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          // 累加
          Value *MemCallIncr = IRB.CreateAdd(MemCallCount, ConstantInt::get(Int32Ty, call_cnt));
          IRB.CreateStore(MemCallIncr, MemCallPtrIdx)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      }
      
      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;

    }
  }
  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
