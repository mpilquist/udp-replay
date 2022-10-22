//> using scala "3.2.0"
//> using packaging.output "udpreplay"
//> using repository "sonatype-s01:snapshots"
//> using lib "co.fs2::fs2-io::3.3.0"
//> using lib "co.fs2::fs2-protocols::3.3.0"
//> using lib "com.armanbilge::decline::2.2.1-SNAPSHOT"

import cats.data.NonEmptyList
import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all.*
import com.comcast.ip4s.*
import com.monovore.decline.*
import fs2.{Chunk, Stream}
import fs2.io.file.{Files, Path}
import fs2.io.net.{Datagram, Network}
import fs2.protocols.pcap.CaptureFile
import fs2.timeseries.TimeStamped
import scala.concurrent.duration.*

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
      val dryRun = Opts.flag("dryrun", help = "If set, no output is performed").orFalse
      val verbose = Opts.flag("verbose", help = "If set, each packet is logged to stdout").orFalse
      (file, timescale, destination, portMappings, dryRun, verbose).tupled
    }
    command.parse(args) match
      case Left(help) => IO(System.err.println(help)).as(ExitCode(-1))
      case Right((file, timescale, destination, portMapping, dryRun, verbose)) =>
        replay(Path(file), timescale, destination, portMapping, dryRun, verbose).compile.drain.as(ExitCode.Success)

  def replay(file: Path, timescale: Double, destination: Host, portMap: Port => Option[Port], dryRun: Boolean, verbose: Boolean): Stream[IO, Nothing] =
    Files[IO]
      .readAll(file)
      .through(CaptureFile.udpDatagrams.toPipeByte)
      .through(TimeStamped.throttle(timescale, 1.second))
      .map(_.value)
      .through(if verbose then logPacket else identity)
      .through(changeDestination(destination, portMap))
      .through(if dryRun then _.drain else sendAll)

  def changeDestination(destination: Host, portMap: Port => Option[Port])(datagrams: Stream[IO, CaptureFile.DatagramRecord]): Stream[IO, Datagram] =
    Stream.eval(destination.resolve[IO]).flatMap { destinationIp =>
      datagrams.flatMap(packet =>
        portMap(packet.udp.destinationPort) match
          case Some(destPort) =>
            Stream(Datagram(SocketAddress(destinationIp, destPort), packet.payload))
          case None => Stream.empty
      )
    }

  def logPacket(datagrams: Stream[IO, CaptureFile.DatagramRecord]): Stream[IO, CaptureFile.DatagramRecord] =
    datagrams.evalTap { d =>
      val src = SocketAddress(d.ip.sourceIp, d.udp.sourcePort)
      val dest = SocketAddress(d.ip.destinationIp, d.udp.destinationPort)
      IO.println(s"$src --> $dest") *>
        IO(d.payload.toByteVector.printHexDump()) *> IO.println("")
    }

  def sendAll(datagrams: Stream[IO, Datagram]): Stream[IO, Nothing] =
    Stream.resource(Network[IO].openDatagramSocket()).flatMap { socket =>
      datagrams.through(socket.writes)
    }
