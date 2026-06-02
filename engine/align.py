def align(mapping, eval_result, evidence_record):
    return {
        "capability": mapping["capability"],
        "title": mapping.get("title", mapping["capability"]),
        "result": eval_result["result"],
        "violations": list(eval_result.get("violations", [])),
        "evidence_ref": evidence_record.record_hash,
        "collected_at": evidence_record.collected_at,
        "frameworks": {
            "fedramp-20x": [
                {"ksi": k["id"], "obligation": k.get("obligation", "required")}
                for k in mapping.get("ksis", [])
            ],
            "nist-800-53-rev5": list(mapping.get("nist_controls", [])),
        },
    }
