# package: Anak Cryptography with Fractal Numerical Algorithm FNA
# author: Mario Rossano aka Anak, www.netlogicalab.com, www.netlogica.it; software@netlogicalab.com; software@netlogica.it
# birthday 05/08/1970; birthplace: Italy
# Validation FILE

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

package Crypt::FNA::Validation;

	use strict;
	use warnings;

	my $fna_default_values= (
		{
			r => 7,
			angle => [0,60,-60,0],
			square => 4096,
			background => [255,255,255],
			foreground => [0,0,0],
			magic => 3,
			zoom => 2
		}
	);
	
	sub new {
		my $class = shift;
		my $init  = shift;
		my $self={};

		bless $self,$class;
		
		$self->intercept($init->{intercept});

		return $self	
	}
	
	sub intercept {
		my $self=shift;
		if (@_) {
			$self->{intercept}=shift
		}
		return $self->{intercept}
	}

	sub method_new_fna {
		my $self=shift;
		my @error_messages="";
		@{$self->intercept->{message}}=();
		
		$self->intercept->{r}.="";
		if ($self->intercept->r eq "" | $self->intercept->r eq "0") {
			$self->intercept->{r}=$fna_default_values->{r}
		} else {
			if ($self->intercept->r=~/[^0-9.]/) {
				push(@error_messages,0);
				$self->intercept->{r}=$fna_default_values->{r}
			} 
		}

		if (!$self->intercept->angle) {
			@{$self->intercept->{angle}}=@{$fna_default_values->{angle}}
		} else {
			for (my $k=0;$k<scalar(@{$self->intercept->angle});$k++) {
				if (${$self->intercept->angle}[$k]=~/[^0-9.+-]/) {
					push(@error_messages,5);
					@{$self->intercept->angle}=@{$fna_default_values->{angle}};
					last
				}
			}
		}

		$self->intercept->{square}.="";
		if ($self->intercept->square eq "" | $self->intercept->square eq "0") {
			$self->intercept->{square}=$fna_default_values->{square}
		} else {
			if ($self->intercept->square=~/[^0-9.]/) {
				push(@error_messages,2);
				$self->intercept->{square}=$fna_default_values->{square}
			}
		}

		if (!$self->intercept->background) {
			@{$self->intercept->{background}}=@{$fna_default_values->{background}}
		} else {
			 if (scalar(@{$self->intercept->background})>3) {
				push(@error_messages,13);
				@{$self->intercept->background}=@{$fna_default_values->{background}}
			 } else {
				for (my $k=0;$k<scalar(@{$self->intercept->background});$k++) {
					if (${$self->intercept->background}[$k]=~/[^0-9]/) {
						push(@error_messages,12);
						@{$self->intercept->background}=@{$fna_default_values->{background}}
					} else {
						if (${$self->intercept->background}[$k]>255) {
							push(@error_messages,13);
							@{$self->intercept->background}=@{$fna_default_values->{background}}
						}
					}
				}
			}
		}

		if (!$self->intercept->foreground) {
			@{$self->intercept->{foreground}}=@{$fna_default_values->{foreground}}
		} else {
			if (scalar(@{$self->intercept->foreground})>3) {
				push(@error_messages,15);
				@{$self->intercept->foreground}=@{$fna_default_values->{foreground}}
			} else {
				for (my $k=0;$k<scalar(@{$self->intercept->foreground});$k++) {
					if (${$self->intercept->foreground}[$k]=~/[^0-9]/) {
						push(@error_messages,14);
						@{$self->intercept->foreground}=@{$fna_default_values->{foreground}}
					} else {
						if (${$self->intercept->foreground}[$k]>255) {
							push(@error_messages,15);
							@{$self->intercept->foreground}=@{$fna_default_values->{foreground}}
						}
					}
				}
			}
		}

		$self->intercept->{magic}.="";
		if ($self->intercept->magic eq "") {
			$self->intercept->{magic}=$fna_default_values->{magic}
		} else {
			if ($self->intercept->magic=~/[^0-9]/) {
				push(@error_messages,20);
				$self->intercept->{magic}=$fna_default_values->{magic}
			}
		}
		
		@{$self->intercept->message}=@error_messages;
		@error_messages="";
		return @{$self->intercept->message}
	}

	sub param_zoom_fna {
		my $self=shift;

		if (${$self->intercept}[0] =~ /[^0-9.]/) {
			push(@{$self->intercept->[1]->{message}},18);
			${$self->intercept}[0]=$fna_default_values->{zoom}
   		}
  		return (${$self->intercept}[0],@{@{$self->intercept}[1]->{message}})
		
	}

	sub open_file {
		my $self=shift;
		
		push(@{$self->intercept->[1]->{message}},${$self->intercept}[0]);
		return @{@{$self->intercept}[1]->{message}}
	}
1;