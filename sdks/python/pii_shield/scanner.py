import os
import json
from dataclasses import dataclass, asdict
from typing import Optional
from wasmtime import Engine, Linker, Store, Config, Module, WasiConfig

@dataclass
class PiiShieldConfig:
    entropy_threshold: Optional[float] = None
    salt: Optional[str] = None
    confidence_score: Optional[float] = None
    fail_policy: str = "open"

class PiiShield:
    def __init__(self, config: PiiShieldConfig = None, wasm_path: str = None):
        self.config = config or PiiShieldConfig()
        
        if not wasm_path:
            # Default to the root of the plugin for testing, or inside the package
            wasm_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "pii-shield-wasi.wasm")
            if not os.path.exists(wasm_path):
                wasm_path = os.path.join(os.path.dirname(__file__), "pii-shield-wasi.wasm")
        
        cfg = Config()
        self.engine = Engine(cfg)
        self.linker = Linker(self.engine)
        
        # Configure WASI
        self.linker.define_wasi()
        self.store = Store(self.engine)
        wasi_cfg = WasiConfig()
        self.store.set_wasi(wasi_cfg)
        
        self.module = Module.from_file(self.engine, wasm_path)
        self.instance = self.linker.instantiate(self.store, self.module)
        
        # Go 1.24+ wasi reactors must be initialized
        exports = self.instance.exports(self.store)
        if "_initialize" in exports:
            exports["_initialize"](self.store)
        
        # Extracted functions
        self.memory = exports["memory"]
        self.allocate = exports["allocate"]
        self.free_mem = exports["free"]
        self.init_config = exports["init_config"]
        self.redact_fn = exports["redact"]
        
        # Sync config
        cfg_dict = {}
        if self.config.entropy_threshold is not None:
            cfg_dict["entropy_threshold"] = self.config.entropy_threshold
        if self.config.salt is not None:
            cfg_dict["salt"] = self.config.salt
        if self.config.confidence_score is not None:
            cfg_dict["confidence_score"] = self.config.confidence_score
            
        cfg_json = json.dumps(cfg_dict).encode("utf-8")
        if len(cfg_json) > 0:
            cfg_ptr = self.allocate(self.store, len(cfg_json))
            if cfg_ptr != 0:
                mem_bytes = self.memory.data_ptr(self.store)
                import ctypes
                ctypes.memmove(mem_bytes + cfg_ptr, cfg_json, len(cfg_json))
                self.init_config(self.store, cfg_ptr, len(cfg_json))
                self.free_mem(self.store, cfg_ptr, len(cfg_json))

    def redact(self, input_str: str) -> str:
        if not input_str:
            return input_str
            
        try:
            input_bytes = input_str.encode('utf-8')
            length = len(input_bytes)
            
            ptr = self.allocate(self.store, length)
            if ptr == 0:
                if self.config.fail_policy == "closed":
                    return "[PII_SHIELD_DROP: FATAL_ERROR]"
                return input_str
                
            mem_bytes = self.memory.data_ptr(self.store)
            import ctypes
            ctypes.memmove(mem_bytes + ptr, input_bytes, length)
            
            packed_result = self.redact_fn(self.store, ptr, length)
            
            # The result is uint64: ptr in high 32 bits, len in low 32 bits
            result_ptr = (packed_result >> 32) & 0xFFFFFFFF
            result_len = packed_result & 0xFFFFFFFF
            
            result_str = input_str
            if result_ptr != 0 and result_len != 0:
                # Need to get memory pointer again in case it moved
                mem_bytes = self.memory.data_ptr(self.store)
                result_bytes = ctypes.string_at(mem_bytes + result_ptr, result_len)
                result_str = result_bytes.decode('utf-8')
                self.free_mem(self.store, result_ptr, result_len)
                
            self.free_mem(self.store, ptr, length)
            return result_str
            
        except Exception:
            if self.config.fail_policy == "closed":
                return "[PII_SHIELD_DROP: FATAL_ERROR]"
            return input_str
