import { readFileSync, writeFileSync } from 'fs';

interface Finding {
    ruleId: string;
    severity: string;
}

interface ScanResult {
    score: number;
    grade: string;
    findings: Finding[];
}

interface TargetResult {
    target: string;
    stars: number;
    scan: ScanResult;
}

function analyzeData() {
    console.log("Analyzing empirical scan data...");
    
    const rawData = readFileSync('data/empirical_study_results.json', 'utf-8');
    const results: TargetResult[] = JSON.parse(rawData);

    // Filter out malformed entries (where score is missing)
    const validResults = results.filter(repo => 
        repo && repo.scan && typeof repo.scan.score === 'number'
    );

    const totalServers = validResults.length;
    
    if (totalServers === 0) {
        console.log("Error: No valid scan results containing a security score were found.");
        return;
    }

    let totalScore = 0;
    const gradeDistribution: Record<string, number> = { 'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0 };
    const severityCounts: Record<string, number> = { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0 };
    const ruleCounts: Record<string, number> = {};
    let vulnerableServersCount = 0;

    validResults.forEach(repo => {
        totalScore += repo.scan.score;
        
        if (gradeDistribution[repo.scan.grade] !== undefined) {
            gradeDistribution[repo.scan.grade]++;
        }

        // Check if findings array exists before iterating
        if (Array.isArray(repo.scan.findings)) {
            const hasHighOrCritical = repo.scan.findings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
            if (hasHighOrCritical) {
                vulnerableServersCount++;
            }

            repo.scan.findings.forEach(finding => {
                // Count Severities
                if (severityCounts[finding.severity] !== undefined) {
                    severityCounts[finding.severity]++;
                }
                
                // Count Rule Classes (extracting the prefix, e.g., 'CMD' from 'CMD-001')
                const ruleClass = finding.ruleId.split('-')[0];
                ruleCounts[ruleClass] = (ruleCounts[ruleClass] || 0) + 1;
            });
        }
    });

    const averageScore = Math.round(totalScore / totalServers);
    const vulnerabilityPercentage = ((vulnerableServersCount / totalServers) * 100).toFixed(1);

    const report = `
===================================================
  MCP ECOSYSTEM SECURITY ANALYSIS (N=${totalServers})
===================================================

[ OVERVIEW ]
Total Valid Servers Analyzed: ${totalServers}
Average Security Score: ${averageScore}/100
Servers with HIGH/CRITICAL Risks: ${vulnerableServersCount} (${vulnerabilityPercentage}%)

[ GRADE DISTRIBUTION ]
A (Excellent): ${gradeDistribution['A']}
B (Good):      ${gradeDistribution['B']}
C (Fair):      ${gradeDistribution['C']}
D (Poor):      ${gradeDistribution['D']}
F (Failing):   ${gradeDistribution['F']}

[ VULNERABILITY SEVERITY BREAKDOWN ]
CRITICAL: ${severityCounts['CRITICAL']}
HIGH:     ${severityCounts['HIGH']}
MEDIUM:   ${severityCounts['MEDIUM']}
LOW:      ${severityCounts['LOW']}

[ TOP VULNERABILITY CLASSES ]
${Object.entries(ruleCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([rule, count]) => `${rule}: ${count} findings`)
    .join('\n')}

===================================================
`;

    console.log(report);
    writeFileSync('data/paper_metrics.txt', report);
    console.log(`\nFiltered out ${results.length - totalServers} malformed records.`);
    console.log("Analysis saved to data/paper_metrics.txt");
}

analyzeData();