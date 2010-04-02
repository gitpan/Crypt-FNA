# package: Anak Cryptography with Fractal Numerical Algorithm FNA
# author: Mario Rossano aka Anak, www.netlogicalab.com, www.netlogica.it; software@netlogicalab.com; software@netlogica.it
# birthday 05/08/1970; birthplace: Italy
# LIBRARY FILE

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

package FNA;

# caricamento lib
	use strict;
	use warnings;
	use Crypt::FNA::Validation;
# fine caricamento lib

our $VERSION =  '0.01';
use constant pi => 3.141592;

# metodi ed attributi

	sub new {
		my $class = shift;
		my $init  = shift;
		my $self={};

		bless $self,$class;
		
		$self->r($init->{r});
		$self->angle($init->{angle});
		$self->square($init->{square});
		$self->background($init->{background});
		$self->foreground($init->{foreground});
		$self->magic($init->{magic});
		$self->message($init->{message});

		my $validate=Crypt::FNA::Validation->new({intercept => $self});
		$validate->method_new_fna($self);
		
		return $self	
	}
	
		sub r {
			my $self=shift;
			if (@_) {
				$self->{r}=shift
			}
			return $self->{r}
		}
		sub angle {
			my $self=shift;
			if (@_) {
				$self->{angle}=shift
			}
			return $self->{angle}
		}
		sub square {
			my $self=shift;
			if (@_) {
				$self->{square}=shift
			}
			return $self->{square}
		}
		sub background {
			my $self=shift;
			if (@_) {
				$self->{background}=shift
			}
			return $self->{background}
		}
		sub foreground {
			my $self=shift;
			if (@_) {
				$self->{foreground}=shift
			}
			return $self->{foreground}
		}
		sub magic {
			my $self=shift;
			if (@_) {
				$self->{magic}=shift
			}
			return $self->{magic}
		}
		sub message {
			my $self=shift;
			if (@_) {
				$self->{message}=shift
			}
			return $self->{message}
		}
	
	sub make_fract {
		my $self=shift;
		my $png_filename=shift;
		my $zoom=shift;

		(my $ro,my @initial_angle)=$self->set_starting_angle();
		(my $nx,my $ny,my $di)=$self->init_geometry($ro);

		my $load_this_package=eval("require GD::SIMPLE;");
		$load_this_package.='';
		if ($load_this_package eq '') {
			push(@{$self->{message}},16);
			return
		}

		#controllo zoom, solo valori numerici e > 0
			my $validate=Crypt::FNA::Validation->new({intercept => [$zoom,$self]});
			($zoom,@{$self->message})=$validate->param_zoom_fna($self);
		#fine controllo zoom

		my $img = GD::Simple->new($self->square,$self->square);
			$img->fgcolor(@{$self->background});	 			# foreground
			$img->bgcolor(@{$self->background}); 			# background
			$img->rectangle(0,0,$self->square,$self->square); 	# campisce il quadrato
			$img->fgcolor(@{$self->foreground}); 				# foreground

		$img->move($nx,$ny);

		for (my $k=0;$k<$ro**($self->r);$k++) {
			${$self->angle}[$k]=$self->evaluate_this_angle($k,$ro) if $k>=$ro;
			($nx,$ny)=$self->evaluate_this_coords($k,$zoom,$nx,$ny,$di);
			$img->lineTo($nx,$ny)
		}
		
		my $fh_pngfile;
		open $fh_pngfile,'>',$png_filename.'.png' or do {
			push(@{$self->{message}},11);
			return
		};
			binmode $fh_pngfile;
			print $fh_pngfile $img->png;
		close $fh_pngfile;
		@{$self->angle}=@initial_angle
	}

	sub encrypt_file {
		my $self=shift;
		my $name_plain_file=shift;
		my $name_encrypted_file=shift;

		(my $ro,my @initial_angle)=$self->set_starting_angle();
		(my $nx,my $ny,my $di)=$self->init_geometry($ro);
	 	
		#  incremento del magic_number in modo da rendere complessa la crittoanalisti basandosi sul raggio vettore calcolato in base allo square iniziale
		$di+=$self->magic;
		$nx=$nx/$self->magic; # ascissa iniziale
		$ny=$ny/$self->magic; # ordinata iniziale;

		my ($this_byte,$byte_dec);
		my $byte_pos=0;
		
		my ($fh_plain,$fh_encrypted);
		open $fh_plain,'<',$name_plain_file or do {
			push(@{$self->{message}},7);
			return
		};
			binmode $fh_plain;
			open $fh_encrypted,'>',$name_encrypted_file or do {
				push(@{$self->{message}},8);
				return
			};
 				while (!eof($fh_plain)) {
					read($fh_plain,$this_byte,1);

					$byte_dec=unpack('C',$this_byte);
					$byte_dec+=$self->magic+1;

 					# chiamata ricorsiva
					($nx,$ny,$byte_pos)=$self->crypt_fract($ro,1,$di,$nx,$ny,$byte_dec,$byte_pos);
					print $fh_encrypted $nx."\n".$ny."\n"
				}
			close ($fh_encrypted);
		close ($fh_plain);
		@{$self->angle}=@initial_angle
	}
	
	sub encrypt_scalar {
		my $self=shift;
		my $string=shift;

		(my $ro,my @initial_angle)=$self->set_starting_angle();
		(my $nx,my $ny,my $di)=$self->init_geometry($ro);
		
		# incremento del magic_number in modo da rendere maggiormente complessa l'individuazione della parte di chiave "di" alla crittoanalisi
		$di+=$self->magic;
		$nx=$nx/$self->magic; # ascissa iniziale
		$ny=$ny/$self->magic; # ordinata iniziale;
		
		my $char_code;
		my $char_pos=0;
		my @encrypted;

		for (split(//,$string)) {
			$char_code=unpack('C',$_);
			$char_code+=$self->magic+1;# maschero il codice carattere
			($nx,$ny,$char_pos)=$self->crypt_fract($ro,1,$di,$nx,$ny,$char_code,$char_pos); # chiamata ricorsiva
			push(@encrypted,($nx,$ny))
		}
		@{$self->angle}=@initial_angle;
		return (@encrypted)
	}

	sub decrypt_file {
		my $self=shift;
		my $name_encrypted_file=shift;
		my $name_decrypted_file=shift;

		(my $ro,my @initial_angle)=$self->set_starting_angle();
		(my $nx,my $ny,my $di)=$self->init_geometry($ro);

		$di+=$self->magic;
		$nx=$nx/$self->magic; # ascissa iniziale
		$ny=$ny/$self->magic; # ordinata iniziale;

		my $from_vertex=0;
		my ($this_byte,$this_byte_dec,$this_vertex,$x_coord,$y_coord);

		my ($fh_encrypted,$fh_decrypted);
		open $fh_encrypted,'<',$name_encrypted_file or do {
			push(@{$self->{message}},9);
			return
		};
			open $fh_decrypted,'>',$name_decrypted_file or do {
				push(@{$self->{message}},10);
				return
			};
				binmode $fh_decrypted;

				while (!eof($fh_encrypted)) {
					$x_coord=<$fh_encrypted>;$y_coord=<$fh_encrypted>;
					chop($x_coord,$y_coord);
					# ho usato chop perchè l'ultimo carattere è certamente \n e chop è più veloce di chomp

					for (my $vertex=$from_vertex;$vertex<256+$from_vertex+$self->magic+1;$vertex++){
						($nx,$ny,$this_vertex)=$self->crypt_fract($ro,1,$di,$nx,$ny,1,$vertex);
						if ($nx eq $x_coord && $ny eq $y_coord) {
						
							$this_byte_dec=$this_vertex-$from_vertex-$self->magic-1;
							$this_byte=pack('C',$this_byte_dec);
							print $fh_decrypted $this_byte;
							
							#imposto il from per ripartire il ciclo for dal punto giusto alla prossima iterazione del while, quando ripartirà il for
							$from_vertex=$this_vertex;
							last
						}
					} # fine for
				} # fine ciclo while
			close $fh_decrypted;
		close $fh_encrypted;
		@{$self->angle}=@initial_angle
	}

	sub crypt_fract {
		my $self=shift;
		my $ro=shift;
		my $zoom=shift;
		my $di=shift;
		my $nx=shift;
		my $ny=shift;
		my $value_dec=shift;
		my $pos=shift;
		
		for (my $k=$pos;$k<($pos+$value_dec);$k++) {
			${$self->angle}[$k]=$self->evaluate_this_angle($k,$ro) if $k>=$ro;
			($nx,$ny)=$self->evaluate_this_coords($k,$zoom,$nx,$ny,$di)
		}
		return($nx,$ny,$pos+$value_dec)
	}

	# fine metodi e proprietà oggetto

	# subroutine di servizio

	sub set_starting_angle {
		my $self=shift;
		my $ro=scalar(@{$self->angle});
		
		my @initial_angle;
		
		#conversione in radianti
		for (my $k=0;$k<$ro;$k++) {
			push(@initial_angle,${$self->angle}[$k]);
			${$self->angle}[$k]=${$self->angle}[$k]*pi/180
		}
		return ($ro,@initial_angle)
	}

	sub init_geometry {
		my $self=shift;
		my $ro=shift;
		
		my $di=int(($self->square/$ro**$self->r)*10000)/5000; # lunghezza di un segmento di curva frattale
		while ($di<5) { # qualora la dimensione sia troppo esigua per la visualizzazione e calcolo, aumento di una unità e moltiplico per il valore precedente (aumento di 1 perchè se di<1 otterrei dei numeri tendenti a zero all'aumentare del numero dei cicli in un loop infinito)
			$di=$di*(1+$di)
		}
		my $nx=$self->square/2; # ascissa iniziale
		my $ny=$self->square/2; # ordinata iniziale
		return ($nx,$ny,$di)
	}

	# functions calcolo angoli e coordinate
	
	sub evaluate_this_angle {
		my $self=shift;
		my $k=shift;
		my $ro=shift;

		return ${$self->angle}[g($k,$ro)]+${$self->angle}[p($k,$ro)]
	}

	sub evaluate_this_coords {
		my $self=shift;
		my $k=shift;
		my $zoom=shift;
		my $nx=shift;
		my $ny=shift;
		my $di=shift;

		if (!$zoom) {$zoom=1};
		$nx=int(10**8*($nx-$di*$zoom*cos(${$self->angle}[$k])))/10**8;
		$ny=int(10**8*($ny-$di*$zoom*sin(${$self->angle}[$k])))/10**8;

		return ($nx,$ny)
	}

 	# ramo o gruppo di {F}
	sub g {
		my $k=shift;
		my $ro=shift;

		my $n=int($k/$ro);
		return $n
	}
 	
 	# posizione nel ramo
	sub p {
		my $k=shift;
		my $ro=shift;

		my $n=$k-$ro*g($k,$ro);
		return $n
	}

	# fine function per identificazione direzioni genitore

# end subroutine
1;