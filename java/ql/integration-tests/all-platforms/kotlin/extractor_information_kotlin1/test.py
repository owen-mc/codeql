from create_database_utils import *

run_codeql_database_create(["kotlinc -J-Xmx2G -language-version 1.9 SomeClass.kt"], lang="java")
