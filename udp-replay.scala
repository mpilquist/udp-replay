//> using scala "3.1.2"
//> using lib "co.fs2::fs2-io:3.2.11"
//> using lib "co.fs2::fs2-protocols:3.2.11"
//> using lib "com.monovore::decline::2.2.0"

import cats.data.NonEmptyList
import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all.*
import com.comcast.ip4s.*
import com.monovore.decline.*
import fs2.{Chunk, Stream}
import fs2.io.file.{Files, Path}
import fs2.io.net.{Datagram, Network}

object UdpReplay extends IOApp:
  def run(args: List[String]) =
    val command = Command(
      name = "udp-replay",
      header = "Replays UDP packets from a pcap file"
    ) {
      val file = Opts.argument[String](metavar = "file")
      val timescale = Opts.option[Double](
        "timescale",
        short = "t",
        metavar = "factor",
        help = "Speed at which replay occurs. 1.0 for replay at recorded rate, 2.0 for double speed, etc."
      ).withDefault(1.0)
      val destination = Opts.option[String](
        "destination",
        short = "d",
        metavar = "host",
        help = "Destination host to send replayed packets to."
      ).withDefault("127.0.0.1").mapValidated(h => Host.fromString(h).toValid(NonEmptyList.of(s"\"$h\" not a valid host")))
      val portMappings = Opts.options[String](
        "port",
        short = "p",
        metavar = "port-or-port-mapping",
        help = """When specified, datagrams that match the specified port(s) are replayed - if a mapping is specified, the destination port is modified before being replayed. For example, "-p 5555" replays any datagrams with destination port 5555 whereas "-p 5555:4444" changes the destination port to 4444. If not specified, then all datagrams in the input are replayed."""
      ).mapValidated { strings =>
        strings.traverse { s =>
          Port.fromString(s).map(p => (p, p)).orElse {
            s.split(":", 2) match
              case Array(from, to) =>
                (Port.fromString(from), Port.fromString(to)).tupled
          }.toValid(NonEmptyList.of(s"\"$s\" not a port or a port mapping"))
        }
      }.orNone.map { portMappings =>
        portMappings.map(_.toList.toMap.get).getOrElse((p: Port) => Some(p))
      }
      (file, timescale, destination, portMappings).tupled
    }
    command.parse(args) match
      case Left(help) => IO(System.err.println(help)).as(ExitCode(-1))
      case Right((file, timescale, destination, portMapping)) =>
        replay(Path(file), timescale, destination, portMapping).compile.drain.as(ExitCode.Success)

  case class CapturedPacket(
    source: SocketAddress[IpAddress],
    destination: SocketAddress[IpAddress],
    payload: Chunk[Byte])

  def replay(file: Path, timescale: Double, destination: Host, portMap: Port => Option[Port]): Stream[IO, Nothing] =
    datagramsInPcapFile(file, timescale).through(sendAll(destination, portMap))

  def datagramsInPcapFile(file: Path, timescale: Double): Stream[IO, CapturedPacket] =
    import fs2.interop.scodec.StreamDecoder
    import fs2.timeseries.TimeStamped
    import fs2.protocols.*
    import fs2.protocols.pcap.{CaptureFile, LinkType}
    import scala.concurrent.duration.*

    val decoder: StreamDecoder[TimeStamped[CapturedPacket]] = CaptureFile.payloadStreamDecoderPF {
      case LinkType.Ethernet =>
        for
          ethernetHeader <- ethernet.EthernetFrameHeader.sdecoder
          ipHeader <- ip.Ipv4Header.sdecoder(ethernetHeader)
          udpDatagram <- ip.udp.DatagramHeader.sdecoder(ipHeader.protocol)
          payload <- StreamDecoder.once(scodec.codecs.bytes)
        yield CapturedPacket(
          SocketAddress(ipHeader.sourceIp, udpDatagram.sourcePort),
          SocketAddress(ipHeader.destinationIp, udpDatagram.destinationPort),
          Chunk.byteVector(payload)
        )
    }

    Files[IO]
      .readAll(file)
      .through(decoder.toPipeByte)
      .through(TimeStamped.throttle(timescale, 1.second))
      .map(_.value)

  def sendAll(destination: Host, portMap: Port => Option[Port])(datagrams: Stream[IO, CapturedPacket]): Stream[IO, Nothing] =
    Stream.eval(destination.resolve[IO]).flatMap { destinationIp =>
      Stream.resource(Network[IO].openDatagramSocket()).flatMap { socket =>
        datagrams.flatMap(packet =>
          portMap(packet.destination.port) match
            case Some(destPort) =>
              Stream(Datagram(SocketAddress(destinationIp, destPort), packet.payload))
            case None => Stream.empty
        ).through(socket.writes)
      }
    }
