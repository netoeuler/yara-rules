rule Cerber_static
{
	meta:
		description = "Detect Cerber with static strings without execution"
		author = "@netonightmare"
		date = "11/01/2023"
		license = "DRL 1.1"

	strings:
		$s1 = "2222222GwwwwG222222"
		$s2 = "2222222Gwwww4222222"
		$s3 = "22222244wwww8822226"
		$s4 = "66222288wwww8866666"
		$s5 = "77777889wwww9887777"
	condition:
		uint16(0) == 0x5A4D and all of them
}

rule Cerber_duringExecution
{

	meta:
			description = "Detect Cerber with strings during execution"
			author = "@netonightmare"
			date = "11/01/2023"
			license = "DRL 1.1"

	strings:
		$s1 = "11111kicu4p3050f55f298b5211cf2bb82200aa00bdce0bf"
	condition:
		uint16(0) == 0x5A4D and all of them
}