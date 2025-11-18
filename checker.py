import pandas as pd

def main():
    print("#######################################################################")
    print("#  _     _     _     _      ____  _     _____ ____  _  __ _____ ____  #")
    print("# / \ |\/ \ /\/ \   / \  /|/   _\/ \ /|/  __//   _\/ |/ //  __//  __\ #")
    print("# | | //| | ||| |   | |\ |||  /  | |_|||  \  |  /  |   / |  \  |  \/| #")
    print("# | \// | \_/|| |_/\| | \|||  \__| | |||  /_ |  \__|   \ |  /_ |    / #")
    print("# \__/  \____/\____/\_/  \|\____/\_/ \|\____\\____/\_|\_\\____\\_/\_\ #")
    print("#                                                                     #")
    print("# By TIVIT - Luis Eduardo Uribe                                       #")
    print("#######################################################################")

    # Define global variables
    EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    KEV_CSV_URL = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'

    KEV_BOOST = 5.0
    MALWARE_BOOST = 3.0
    EXPLOIT_BOOST = 2.0

    # Cargamos el CSV generado por Tenable One
    print("Cargando archivo CSV")
    vulnerabilities_df = pd.read_csv('data/tenable_one_csv.csv', encoding="latin1")
    print("Cargando el listado KEV")
    kev_df = pd.read_csv(KEV_CSV_URL)

    print("Correlacionando con el KEV")
    vulnerabilities_df['CVEKEY'] = vulnerabilities_df['CVE'].astype(str).str.strip().str.upper()
    kev_df['cveID'] = kev_df['cveID'].astype(str).str.strip().str.upper()
    vulnerabilities_df['kev'] = vulnerabilities_df['CVEKEY'].isin(kev_df['cveID'].unique())

    print("Cargando el listado de EPSS")
    epss_df = pd.read_csv(EPSS_CSV_URL, compression='gzip', skiprows=[0],header=0)
    epss_df.rename(columns={"cve": 'cve_epss'}, inplace=True)

    print("Correlacionando con el EPSS")
    vulnerabilities_df = pd.merge(vulnerabilities_df, epss_df, how='left', left_on='CVE', right_on='cve_epss')
    # Se eliminan las columnas que no se requieren
    vulnerabilities_df = vulnerabilities_df.drop('CVEKEY', axis=1)
    vulnerabilities_df = vulnerabilities_df.drop('cve_epss', axis=1)

    # Se llenan los epss en 0.0 
    vulnerabilities_df["epss"] = vulnerabilities_df["epss"].fillna(0.00)

    print("Generando Score de Priorización")
    vulnerabilities_df["exploitable"] = vulnerabilities_df[['Exploit Available', 'Exploited by Nessus', 'CANVAS', 'D2 Elliot', 'Metasploit','Core Exploits', 'ExploitHub']].any(axis=1)

    # Se verifica si existen valores NaN que deban ser reemplazados con 0.0
    vulnerabilities_df['CVSS3 Base Score'] = pd.to_numeric(vulnerabilities_df['CVSS3 Base Score'], errors='coerce').fillna(0.0)
    vulnerabilities_df['CVSS Base Score'] = pd.to_numeric(vulnerabilities_df['CVSS Base Score'], errors='coerce').fillna(0.0)

    vulnerabilities_df['cvss_score'] = vulnerabilities_df["CVSS3 Base Score"]
    vulnerabilities_df.loc[(vulnerabilities_df['CVSS Base Score'] > 0.0) & (vulnerabilities_df['CVSS3 Base Score'] == 0.0), 'cvss_score'] = vulnerabilities_df['CVSS Base Score']

    # Verificamos y regulamos todos los valores para ser booleanos
    vulnerabilities_df['Exploited by Malware'] = vulnerabilities_df['Exploited by Malware'].astype(str).str.upper().isin(['TRUE'])

    vulnerabilities_df["prioritization_score"] = (
        (vulnerabilities_df["cvss_score"] * 0.5)+(vulnerabilities_df["epss"] * 10.0)
    ) * (
        vulnerabilities_df["kev"].apply(lambda x: KEV_BOOST if x else 1.0)
    ) * (
        vulnerabilities_df["Exploited by Malware"].apply(lambda x: MALWARE_BOOST if x else 1.0)
    ) * (
        vulnerabilities_df["exploitable"].apply(lambda x: EXPLOIT_BOOST if x else 1.0)
    )

    vulnerabilities_df = vulnerabilities_df.sort_values(by="prioritization_score", ascending=False)

    vulnerabilities_df.to_csv("data/output.csv", index=False)

    print("Ejecución completada. El archivo 'output.csv' ha sido generado.")

if __name__ == "__main__":
    main()