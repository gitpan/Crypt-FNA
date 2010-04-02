# package: Anak Cryptography with Fractal Numerical Algorithm FNA
# author: Mario Rossano aka Anak, www.netlogicalab.com, www.netlogica.it; software@netlogicalab.com; software@netlogica.it
# birthday 05/08/1970; birthplace: Italy
# EXAMPLES FILE

# Copyright (C) 2009 Mario Rossano aka Anak
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of either:
# CC-NC-BY-SA
# license http://creativecommons.org/licenses/by-nc-sa/2.5/it/
# Creative Commons License: http://i.creativecommons.org/l/by-nc-sa/2.5/it/88x31.png
# FNA Fractal Numerical Algorithm for a new cryptography technology, author Mario Rossano
# is licensed under a:http://creativecommons.org/B/by-nc-sa/2.5/it/ - Creative Commons Attribuzione-Non commerciale-Condividi allo stesso modo 2.5 Italia License
# Permissions beyond the scope of this license may be available at software@netlogicalab.com

# moduli utilizzati

	use strict;
	use warnings;
	use Crypt::FNA;

# fine moduli utilizzati

	# alcuni parametri base di test

		#angle => [0,90,-60,-90,60] 		# chiave
		#angle => [0,90,60,-90,120]		# scorpione
		#angle => [0,60,-60,0]			# von Koch
		#angle => [56,-187,215,64]		# nebulosa gassosa
		#angle => [66,-177,205,64]		# ramo sulla spiaggia
		#angle => [0,80,60,-90,120]		# maschera
		#angle => [-17,80,-60,-95,230]	# merletto

	# fine alcuni parametri base di test

	# implementazione dei metodi FNA

		# costruzione di un oggetto FNA
			my $krypto=FNA->new(
				{
					r=> '8',
					angle =>  [56,-187,215,64],
					square => 4096,
					background => [255,255,255],
					foreground => [0,0,0],
					magic => 2
				}
			);
			
			my $krypto2=FNA->new();
		# fine costruzione di un oggetto FNA

		# disegno di frattali
			$krypto->make_fract('fractal1',6); # nome file png, senza estensione e fattore di zoom
			$krypto2->make_fract('fractal2',.7); # nome file png, senza estensione e fattore di zoom
		
		# crittografia di file
			$krypto->encrypt_file('test.txt','test.fna');

		# ricostruzione di file
			$krypto->decrypt_file('test.fna','test_rebuild.txt');

		# unione dei metodi, ipercrittografia
			$krypto->encrypt_file('test.txt','test2.fna');
				$krypto2->encrypt_file('test2.fna','test3.fna');
				$krypto2->decrypt_file('test3.fna','test2_rebuild.fna');
			$krypto->decrypt_file('test2_rebuild.fna','test3_rebuild.txt');

		# crittografia di una stringa
			my @encrypted_scalar=$krypto->encrypt_scalar('questa è una prova');
			for(@encrypted_scalar) {print $_."\n"}

		# hack ricostruzione stringa 
			my ($fh_testo_criptato,$file_criptato);
			open $fh_testo_criptato, '>',\$file_criptato or die "errore scrittura file\n";
				for (@encrypted_scalar) {print $fh_testo_criptato $_."\n"}
			close $fh_testo_criptato;
			my ($fh_testo_decriptato,$file_decriptato);
			$krypto->decrypt_file(\$file_criptato,\$file_decriptato);

	       # lettura codici errore (salvati nel vettore $krypto->message)
		     $krypto->make_fract("fractal3","3a"); # nome file png e zoom
		     my @errors=@{$krypto->message};
			  foreach my $errors(@errors) {
			       print "> 1-".$errors."\n"
		     }
		     @errors=@{$krypto2->message};
			  foreach my $errors(@errors) {
			       print "> 2-".$errors."\n"
		     }

	# fine implementazione dei metodi FNA

exit
