resource "aws_instance" "web" {
  ami                    = "ami-0e1bed4f06a3b463d"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.allow_tls.id]
  key_name               = "pem_file"
  tags = {
    Name = "JenkinsServer"
  }
  user_data = file("script.sh")
}


resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = "vpc-026d6179478858515"

  tags = {
    Name = "allow_tls"
  }
}

resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv4_allow_all" {
  security_group_id = aws_security_group.allow_tls.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 0
  ip_protocol       = "tcp"
  to_port           = 65535
}

resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv6_allow_all" {
  security_group_id = aws_security_group.allow_tls.id
  cidr_ipv6         = "::/0"
  from_port         = 0
  ip_protocol       = "tcp"
  to_port           = 65535
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.allow_tls.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv6" {
  security_group_id = aws_security_group.allow_tls.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}
# Public key

#Public key and private key name should be same
resource "aws_key_pair" "pem_file" {
  key_name   = "pem_file"
  public_key = tls_private_key.rsa.public_key_openssh
}

#Private key
resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

#save private key in local
resource "local_file" "pem_file" {
  content  = tls_private_key.rsa.private_key_pem
  filename = "pem_file.pem"
}

output "instance_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.web.public_ip
}
