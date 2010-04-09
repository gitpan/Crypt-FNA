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

our $VERSION =  '0.02';
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

# POD SECTION

=head1 NAME

Crypt::FNA

=head1 VERSION

Version 0.02

=head1 DESCRIPTION

FNA stands for Fractal Numerical Algorithm, the symmetrical encryption method
based on two algorithms that I developed for: 1. the 
construction of a family of fractal curves (F) 2. a 
encryption based on these curves. 

A precise description of this algorithm is covered by Article 
on http://www.perl.it/contest/2009 (soon publish).
	

=head1 CONSTRUCTOR
  
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
  
=head2 ATTRIBUTE r

Shows the depth in the calculation of the curve. It 's a number greater than zero, not
necessarily integer. Indicated by the number of corners Ro basis of self-similar structure, the number of
segments forming the curve is given by Ro ** r.

Default value: 7

=head2 ATTRIBUTE angle

Are the angles covered by the recursion algorithm: these angles determines the basic structure
self-similar curve (F). Angles are expressed in sessadecimale system, with values ranging from
-360 And 360 (ie from 0 to 360).

Default value: (56, -187, 215, -64)

=head2 ATTRIBUTE square

It 's the length of the side of a square container of the curve. Square has not only important for the
(If any) graphical representation, but also for encryption, because it is used to calculate the
length of the side of the curve (the square is proportional to ro r **)

Default: 4096

=head2 ATTRIBUTE background

And 'the RGB color background PNG file containing the design curve. The notation is decimal, then with
values ranging from 0 to 255.

Default value: (255,255,255)

=head2 ATTRIBUTE foreground

And 'the RGB color tract in the PNG file containing the design curve. The notation is decimal, then
with values ranging from 0 to 255.

Default value: (0,0,0)

=head2 ATTRIBUTE magic

Indicates the number of vertices of the curve to be skipped during encryption and decryption: Since the algorithm, a
continuous function on the top, skipping some, this is still on top of all the isolated points
(Hence "fair").

Default value: 3

=head1 METHODS

=head2 encrypt_file

encrypt_file decrypt_file method and are the sum: make it useful by applying the mathematical
curves (F). This method carries out a very precise: it encrypt the input file to output file.
The syntax is:

  
  $Krypto-> encrypt_file($name_plain_file, $name_encrypted_file)
  

The input file of any format will be encrypt by the curve (F).

=head2 decrypt_file

The methods and decrypt_file encrypt_file, are summa: make it useful by applying the mathematical
curves (F). This method carries out a very precise: it decrypt the input file (which is to
encrypt_file output method) in the output file (which is the input method encrypt_file).

The syntax is:

  
  $Krypto->decrypt_file ($name_encrypted_file, $name_decrypted_file)
  

The input file is read and decoded through the curve (F), the output file.

=head2 encrypt_scalar

The method encrypt_scalar digit strings: the result of encryption is a vector containing the cryptogram.
The syntax is:
  
  @encrypted_scalar=krypto->encrypt_scalar($this_scalar)
  

Crypt::FNA does not implement, at present, a method for decrypting the encrypted scalar. Anyway, with a little hack, you can decipher even scalars
using the decrypt_file the scalar and writing to a file in volatile memory (we can avoid the file system call to do this).

See examples (inserted in fnatest.pl):

=head2 make_fract

This method is undoubtedly the most impressive and allows you to "touch" the curves that will be applied in cryptographic algorithms.
For the programmer can be useful in your application, show the curve, for example, a hypothetical control panel for managing passwords or
encrypted files in an attachment to forms sent by email and stored on the server.

The graphic file output format is PNG (Portable Network Graphic), accessible from any browser by as many different graphics software.

The syntax is:

  
  $Krypto->make_fract($pngfile, $zoom)
  

1. $pngfile is the name of the png files - without extension "PNG" is inserted automatically
2. $zoom the drawing scale - greater than zero. Default value: 1

The image produced is contained in the square of side $square.


=head1 EXAMPLES

=head2 making FNA object

  
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
  

=head2 draw a fractal curve of {F}

  
  $krypto->make_fract('fractal1',1);
  

=head2 file's encryption

  
  $krypto->encrypt_file('test.txt','test.fna');
  

=head2 file's decryption

  
  $krypto->decrypt_file('test.fna','test_rebuild.txt');
  

=head2 hyperencryption

  
  $krypto->encrypt_file('test.txt','test2.fna');
    $krypto2->encrypt_file('test2.fna','test3.fna');
    $krypto2->decrypt_file('test3.fna','test2_rebuild.fna');
  $krypto->decrypt_file('test2_rebuild.fna','test3_rebuild.txt');
  
  
=head2 scalar encryption

  
  my @encrypted_scalar=$krypto->encrypt_scalar('questa è una prova');
  for(@encrypted_scalar) {print $_."\n"}
  

=head2 hack scalar decryption

  
  # Hack reconstruction string
    # Encryption of a string
      my $stringa_in_chiaro = 'this is a test';
      my @encrypted_scalar = $Krypto->encrypt_scalar($stringa_in_chiaro);
      for (@encrypted_scalar) {print $ _. "\ n"}
 
    # Hack reconstruction string
      my ($fh_testo_criptato, $file_criptato);
      $fh_testo_criptato open, '>', \ $ file_criptato or die "error writing file in memory \ n";
        for (@encrypted_scalar) {print $ fh_testo_criptato $ _. "\ n"}
      close $ fh_testo_criptato;
      my ($fh_testo_decriptato, $stringa_decriptata);
      $Krypto- decrypt_file (\$file_criptato, \$stringa_decriptata);
  # End Hack
  

$stringa_decriptata contains the clear string value

=head2 reading error code

  
  $krypto->make_fract("fractal3","3a"); # nome file png e zoom
  my @errors=@{$krypto->message};
  foreach my $errors(@errors) {
    print "> 1-".$errors."\n"
  }
  @errors=@{$krypto2->message};
  foreach my $errors(@errors) {
    print "> 2-".$errors."\n"
  }
  
=head2 error code

0 Order of the curve is not correct.\nMust necessarily be numeric. Ex. r=7
1 Order of the curve must be a number greater than 0
2 Length Square container is incorrect. Must necessarily be numeric
3 Side of a square container fractal must be a number greater than 0
5 Value of is not correct. Must necessarily be numeric.Default loaded
6 The angle must be expressed in the system sessadecimal (ex. 126.35) Default loaded
7 Error reading sub encrypt, package Crypt: FNA
8 error writing file, package Crypt: FNA sub encrypt
9 read error on sub decrypt myInput package Crypt: FNA
10 write error on sub decrypt MYOUTPUT package Crypt: FNA
11 error writing PNG sub draw_fract package Crypt: FNA
12 error background: only numeric character (RGB)
13 error background: only three number (RGB) from 0 to 255
14 error foreground: only numeric character (RGB)
15 error foreground: only three number (RGB) from 0 to 255
16 error loading GD::Simple, drawing aborted
18 error zoom: the value must be a number greater than zero
19 errors during object instantiation
20 error magic setting

=head1 AUTHOR

Mario Rossano
software@netlogicalab.com
software@netlogica.it
www.netlogicalab.com
skype: anak_the_wolf

=head1 BUGS

Please, send me your alerts to software@netlogica.it

=head1 SUPPORT

Write me :) software@netlogica.it


=head1 COPYRIGHT & LICENSE

FNA by Mario Rossano, http://www.netlogicalab.com

This pod text by Mario Rossano

Copyright (C) 2009 Mario Rossano aka Anak
birthday 05/08/1970; birthplace: Italy

This program is free software; you can redistribute it and/or modify it
under the terms of either:
CC-NC-BY-SA
license http://creativecommons.org/licenses/by-nc-sa/2.5/it/
Creative Commons License: http://i.creativecommons.org/l/by-nc-sa/2.5/it/88x31.png

FNA Fractal Numerical Algorithm for a new cryptography technology, author Mario Rossano
is licensed under a: http://creativecommons.org/B/by-nc-sa/2.5/it/ - Creative Commons Attribuzione-Non commerciale-Condividi allo stesso modo 2.5 Italia License

Permissions beyond the scope of this license may be available at software@netlogicalab.com

