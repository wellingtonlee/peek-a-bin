"""
Peek-a-Bin Ghidra Decompilation Server

REST API that wraps Ghidra's decompiler via pyhidra.
Projects are cached by SHA-256 of the uploaded binary.

Usage:
    python server.py [--port 8765] [--api-key SECRET]
"""
import argparse
import hashlib
import logging
import os
import shutil
import traceback
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

import pyhidra
from fastapi import FastAPI, File, UploadFile, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="Peek-a-Bin Ghidra Server", version="0.1.0")

# CORS for browser access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_DIR = Path.home() / ".peek-a-bin-server" / "projects"
PROJECT_DIR.mkdir(parents=True, exist_ok=True)

# Global state
API_KEY: Optional[str] = None
_programs: dict[str, object] = {}  # projectId -> {ctx, flat_api, program}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catch-all so unhandled errors are logged and returned as JSON."""
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": str(exc)})


def check_auth(authorization: Optional[str] = Header(None)):
    """Verify bearer token if server was started with --api-key."""
    if API_KEY is None:
        return
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization required")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or token != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")


@app.get("/api/v1/ping")
async def ping(authorization: Optional[str] = Header(None)):
    check_auth(authorization)
    ghidra_version = None
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if install_dir:
        # Extract version from path like /opt/ghidra_12.0.4_PUBLIC
        import re
        m = re.search(r"ghidra[_-](\d+\.\d+(?:\.\d+)?)", install_dir, re.IGNORECASE)
        if m:
            ghidra_version = m.group(1)
    return {"version": "0.1.0", "ghidraVersion": ghidra_version}


@app.post("/api/v1/binary")
async def upload_binary(
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
):
    check_auth(authorization)
    data = await file.read()
    sha = hashlib.sha256(data).hexdigest()

    project_path = PROJECT_DIR / sha
    if sha in _programs:
        return {"projectId": sha}

    # Save binary and import into Ghidra
    project_path.mkdir(parents=True, exist_ok=True)
    bin_path = project_path / "binary.exe"
    bin_path.write_bytes(data)

    # Remove stale Ghidra project dir if present (best-effort pre-cleanup)
    ghidra_project_dir = project_path / "binary.exe_ghidra"
    if ghidra_project_dir.exists():
        shutil.rmtree(ghidra_project_dir)
        log.info("Removed existing Ghidra project dir for %s", sha[:12])

    try:
        ctx = pyhidra.open_program(str(bin_path))
        flat_api = ctx.__enter__()
        program = flat_api.getCurrentProgram()

        _programs[sha] = {
            "ctx": ctx,
            "flat_api": flat_api,
            "program": program,
        }
        log.info("Imported binary %s (%d bytes)", sha[:12], len(data))
    except Exception as e:
        if "NotFoundException" not in type(e).__name__:
            log.exception("Import failed for %s", sha[:12])
            raise HTTPException(status_code=500, detail=f"Import failed: {e}")

        # Ghidra 12 throws NotFoundException instead of IOException;
        # pyhidra only catches IOException, so we fall back to direct Java API.
        log.warning("NotFoundException for %s — using direct Ghidra API", sha[:12])
        if ghidra_project_dir.exists():
            shutil.rmtree(ghidra_project_dir)

        try:
            from ghidra.base.project import GhidraProject
            from ghidra.program.flatapi import FlatProgramAPI
            from java.io import File as JavaFile

            project = GhidraProject.createProject(
                str(project_path), "binary.exe_ghidra", False
            )
            program = project.importProgram(JavaFile(str(bin_path)))

            # Ghidra 12's WindowsResourceReferenceAnalyzer crashes without
            # OSGi BundleHost (NPE in GhidraScriptUtil). Disable it if possible,
            # and wrap analyze() so one bad analyzer doesn't abort the import.
            try:
                analyzer_opts = program.getOptions("Analyzers")
                analyzer_opts.setBoolean("Windows x86 PE Resource Reference Analyzer", False)
            except Exception:
                pass  # option name may vary by Ghidra version

            try:
                project.analyze(program)
            except Exception as ae:
                log.warning("Analysis completed with errors for %s: %s (non-fatal)", sha[:12], ae)

            flat_api = FlatProgramAPI(program)

            _programs[sha] = {
                "project": project,
                "flat_api": flat_api,
                "program": program,
            }
            log.info("Imported binary %s via direct API (%d bytes)", sha[:12], len(data))
        except Exception as e2:
            log.exception("Direct API import also failed for %s", sha[:12])
            raise HTTPException(status_code=500, detail=f"Import failed: {e2}")

    return {"projectId": sha}


@app.post("/api/v1/decompile")
async def decompile_function(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    check_auth(authorization)
    body = await request.json()
    project_id = body.get("projectId")
    func_addr = body.get("funcAddr")
    is64 = body.get("is64", False)

    if project_id not in _programs:
        raise HTTPException(status_code=404, detail="Project not found. Upload binary first.")

    entry = _programs[project_id]
    program = entry["program"]

    try:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        decomp = DecompInterface()

        if not decomp.openProgram(program):
            raise RuntimeError(
                "DecompInterface.openProgram() returned false — "
                "native decompiler binary may be missing or not executable"
            )

        try:
            addr_factory = program.getAddressFactory()
            addr = addr_factory.getDefaultAddressSpace().getAddress(func_addr)

            func_mgr = program.getFunctionManager()
            func = func_mgr.getFunctionContaining(addr)
            if func is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"No function at address 0x{func_addr:x}",
                )

            results = decomp.decompileFunction(func, 30, monitor)
            if not results.decompileCompleted():
                err_msg = results.getErrorMessage()
                raise HTTPException(
                    status_code=500,
                    detail=f"Decompilation failed: {err_msg or 'timed out'}",
                )

            decomp_func = results.getDecompiledFunction()
            if decomp_func is None:
                err_msg = results.getErrorMessage()
                raise HTTPException(
                    status_code=500,
                    detail=f"No decompiled output: {err_msg or 'unknown error'}",
                )

            code = decomp_func.getC()

            # Build line map from pcode address mapping
            line_map = []
            high_func = results.getHighFunction()
            if high_func:
                pcode_iter = high_func.getPcodeOps()
                while pcode_iter.hasNext():
                    op = pcode_iter.next()
                    seq = op.getSeqnum()
                    if seq and seq.getTarget():
                        pass  # placeholder for future line mapping

            return {"code": code, "lineMap": line_map}

        finally:
            decomp.closeProgram()

    except HTTPException:
        raise
    except Exception as e:
        log.exception("Decompile error for project=%s addr=%s", project_id, func_addr)
        raise HTTPException(status_code=500, detail=f"Decompile error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Peek-a-Bin Ghidra Server")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--api-key", type=str, default=None, help="Optional bearer token for auth")
    args = parser.parse_args()

    if args.api_key:
        API_KEY = args.api_key

    # Initialize pyhidra (requires GHIDRA_INSTALL_DIR to be set)
    pyhidra.start()

    uvicorn.run(app, host="0.0.0.0", port=args.port)
